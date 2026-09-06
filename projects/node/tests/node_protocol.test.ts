import { describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import type { IdentityNode, SignRequest } from "../src/protocol/node.js";
import { aggregateSignatureShares, computeGroupCommitment } from "../src/crypto/frost.js";
import { createDPoPProof } from "../src/client-sdk/dpop.js";
import { assembleJwt, base64UrlDecode, base64UrlEncode } from "../src/jwt/jwt.js";
import { buildNodeFromFixture, hexToBytes, readFixtureJson, TEST_ISSUER } from "./helpers/nodes.js";
import {
  DEFAULT_REFRESH_LIFETIME_SECONDS,
  buildAccessTokenSigningInput,
  buildRefreshTokenSigningInput,
  newDPoPKeyPair,
} from "./helpers/client.js";
import { aggregateSignOn, assertionFor, runSignOn, startRound } from "./helpers/inproc.js";

/**
 * Node-only properties: the assertion of `/sign-on`, which is the authorization code, and
 * the access token `/sign` mints against it (docs/container-split.md section 14). They
 * exercise `IdentityNode` directly, with the gateway's relay role and the client's
 * aggregation role played by the test. The node holds no session, so every `/sign` input
 * is either in the assertion or range-checked on the spot.
 */

const PASSWORD = "password123";
const USERNAME = "alice";
const ALICE_SUB = "usr_alice_12345";
const CLIENT_ID = "demo_client";
const SCOPE = "openid profile";
const TOKEN_ENDPOINT = `${TEST_ISSUER}/token`;
const GROUP_PUBLIC_KEY = hexToBytes(readFixtureJson("group.json").groupPublicKey);

function freshNodes(): IdentityNode[] {
  return ["node-1.json", "node-2.json", "node-3.json"].map(
    (f) => buildNodeFromFixture(f).node
  );
}

function decodeJwt(token: string) {
  const [h, p] = token.split(".");
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(p, "base64url").toString("utf8")),
  };
}

function verifyToken(token: string): boolean {
  const parts = token.split(".");
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  return ed25519.verify(base64UrlDecode(parts[2]), signingInput, GROUP_PUBLIC_KEY);
}

interface SignOptions {
  grant?: "authorization_code" | "refresh_token";
  refreshExp?: number;
  /** Same round id twice, to show a node refuses to reuse one nonce pair. */
  sameRound?: boolean;
}

/**
 * Runs `/sign` on every node and assembles both tokens from the plaintext shares.
 *
 * Two FROST rounds are opened, one per signature, exactly as the gateway would.
 */
function signTokens(
  nodes: IdentityNode[],
  credential: string,
  proof: string,
  claims: { iat: number; exp: number; jti: string },
  options: SignOptions = {}
): { access_token: string; refresh_token: string; shares: string[]; refreshShares: string[] } {
  const grant = options.grant ?? "authorization_code";
  const accessRoundId = crypto.randomUUID();
  const refreshRoundId = options.sameRound ? accessRoundId : crypto.randomUUID();
  const commitments = nodes.map((n) => ({
    nodeId: n.nodeId,
    ...n.generateCommitment(accessRoundId),
  }));
  const refreshCommitments = options.sameRound
    ? commitments
    : nodes.map((n) => ({ nodeId: n.nodeId, ...n.generateCommitment(refreshRoundId) }));

  const request: SignRequest = {
    grant,
    ...(grant === "authorization_code"
      ? { assertion: credential }
      : { refreshToken: credential }),
    dpopProof: proof,
    claims,
    commitments,
    refreshCommitments,
    allParticipants: nodes.map((n) => n.nodeId),
    ...(options.refreshExp !== undefined ? { refreshExp: options.refreshExp } : {}),
  };

  const responses = nodes.map((n) => {
    const at = commitments.find((c) => c.nodeId === n.nodeId)!;
    const rt = refreshCommitments.find((c) => c.nodeId === n.nodeId)!;
    return n.handleSign(
      { accessRoundId, refreshRoundId },
      request,
      { access: { D: at.D, E: at.E }, refresh: { D: rt.D, E: rt.E } }
    );
  });

  // The claims the nodes signed come out of the credential, so the test reads them from
  // there too rather than assuming what it asked for.
  const identity = JSON.parse(
    Buffer.from(credential.split(".")[1] ?? "", "base64url").toString("utf8")
  );

  const at = buildAccessTokenSigningInput({
    iss: TEST_ISSUER,
    sub: identity.sub,
    aud: identity.client_id,
    scope: identity.scope ?? "",
    cnfJkt: identity.cnf?.jkt,
    ...claims,
  });
  const rt = buildRefreshTokenSigningInput({
    iss: TEST_ISSUER,
    sub: identity.sub,
    clientId: identity.client_id,
    scope: identity.scope ?? "",
    cnfJkt: identity.cnf?.jkt,
    iat: claims.iat,
    exp: options.refreshExp ?? claims.iat + DEFAULT_REFRESH_LIFETIME_SECONDS,
  });

  const assemble = (
    parts: { signingInput: Uint8Array; headerB64: string; payloadB64: string },
    set: typeof commitments,
    shares: string[]
  ): string =>
    assembleJwt(
      parts.headerB64,
      parts.payloadB64,
      aggregateSignatureShares(
        computeGroupCommitment(parts.signingInput, set),
        shares.map((z) => BigInt("0x" + z))
      )
    );

  const shares = responses.map((r) => r.at.z_i);
  const refreshShares = responses.map((r) => r.rt.z_i);
  return {
    access_token: assemble(at, commitments, shares),
    refresh_token: assemble(rt, refreshCommitments, refreshShares),
    shares,
    refreshShares,
  };
}

describe("sign-on: the authentication assertion", () => {
  it("mints an assertion verifiable under the dealer's group public key", () => {
    const nodes = freshNodes();
    const round = startRound(nodes, { username: USERNAME, password: PASSWORD, nonce: "c1" });
    const responses = runSignOn(nodes, round);

    const { assertion } = aggregateSignOn({ round, responses, password: PASSWORD });

    expect(verifyToken(assertion)).toBe(true);
    const { header, payload } = decodeJwt(assertion);
    expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" });
    expect(payload.sub).toBe(ALICE_SUB);
    // aud is the issuer itself: the assertion is addressed to the gateway, not to a client.
    expect(payload.iss).toBe(TEST_ISSUER);
    expect(payload.aud).toBe(TEST_ISSUER);
    expect(payload.nonce).toBe("c1");
    // client_id and scope ride along, because the node keeps nothing to look them up in.
    expect(payload.client_id).toBe(CLIENT_ID);
    expect(payload.scope).toBe(SCOPE);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(30);
  });

  it("uses a preprocessed nonce only once (no Schnorr nonce reuse)", () => {
    const nodes = freshNodes();
    const round = startRound(nodes, { username: USERNAME, password: PASSWORD });
    const mine = round.commitments[0];

    expect(nodes[0].handleSignOn(round.roundId, round.request, { D: mine.D, E: mine.E })).toBeDefined();

    expect(() =>
      nodes[0].handleSignOn(round.roundId, round.request, { D: mine.D, E: mine.E })
    ).toThrowError(/expired or not found on node 1/);
  });

  it("takes sub from its own record and ignores a client-supplied one", () => {
    const nodes = freshNodes();
    const round = startRound(nodes, {
      username: USERNAME,
      password: PASSWORD,
      extra: { sub: "admin" },
    });
    const responses = runSignOn(nodes, round);

    expect(responses.every((r) => r.sub === ALICE_SUB)).toBe(true);

    // The nodes signed and AAD-bound a payload carrying the record's sub, so a client
    // that assumes a spoofed sub cannot even decrypt the shares.
    expect(() =>
      aggregateSignOn({ round, responses, password: PASSWORD, sub: "admin" })
    ).toThrowError(/Invalid password or corrupted share/);
  });

  it("requires the complete commitment set used in round 1", () => {
    const nodes = freshNodes();
    const round = startRound(nodes, { username: USERNAME, password: PASSWORD });
    const responses = runSignOn(nodes, round);

    // All three committed and signed, so dropping one signer's share breaks the signature.
    const partial = aggregateSignOn({ round, responses: responses.slice(0, 2), password: PASSWORD });
    expect(verifyToken(partial.assertion)).toBe(false);

    const complete = aggregateSignOn({ round, responses, password: PASSWORD });
    expect(verifyToken(complete.assertion)).toBe(true);
  });

  it("emits shares without ever checking the password", () => {
    const nodes = freshNodes();
    const round = startRound(nodes, { username: USERNAME, password: "completely wrong" });
    const responses = runSignOn(nodes, round);

    expect(responses).toHaveLength(3);
    expect(responses.every((r) => r.ct_i.length > 0)).toBe(true);
    expect(responses.every((r) => base64UrlDecode(r.toprfPartial).length === 32)).toBe(true);

    // The failure only shows up on the client, at decryption time.
    expect(() =>
      aggregateSignOn({ round, responses, password: "completely wrong" })
    ).toThrowError(/Invalid password or corrupted share/);
  });

  it("binds ciphertext shares to the signing input (no cross-session replay)", () => {
    const nodes = freshNodes();
    const roundA = startRound(nodes, { username: USERNAME, password: PASSWORD, nonce: "session-a" });
    const responsesA = runSignOn(nodes, roundA);

    const roundB = startRound(nodes, { username: USERNAME, password: PASSWORD, nonce: "session-b" });
    const { signingInput: signingInputB } = aggregateSignOn({
      round: roundB,
      responses: runSignOn(nodes, roundB),
      password: PASSWORD,
    });

    expect(() =>
      aggregateSignOn({
        round: roundA,
        responses: responsesA,
        password: PASSWORD,
        signingInputOverride: signingInputB,
      })
    ).toThrowError(/Invalid password or corrupted share/);
  });

  it("rejects an unknown user", () => {
    const nodes = freshNodes();
    const round = startRound(nodes, { username: "mallory", password: PASSWORD });
    const mine = round.commitments[0];

    expect(() =>
      nodes[0].handleSignOn(round.roundId, round.request, { D: mine.D, E: mine.E })
    ).toThrowError(/User not found on node 1/);
  });

  it("refuses a lifetime over 30 seconds, a stale iat, and a foreign issuer", () => {
    const nodes = freshNodes();

    const long = startRound(nodes, {
      username: USERNAME,
      password: PASSWORD,
      lifetimeSeconds: 31,
    });
    expect(() =>
      nodes[0].handleSignOn(long.roundId, long.request, long.commitments[0])
    ).toThrowError(/Assertion lifetime 31s out of range/);

    const stale = startRound(nodes, { username: USERNAME, password: PASSWORD });
    stale.request.iat -= 600;
    stale.request.exp -= 600;
    expect(() =>
      nodes[0].handleSignOn(stale.roundId, stale.request, stale.commitments[0])
    ).toThrowError(/Assertion iat is outside the ±60s window/);

    const elsewhere = startRound(nodes, {
      username: USERNAME,
      password: PASSWORD,
      issuer: "http://evil.test",
    });
    expect(() =>
      nodes[0].handleSignOn(elsewhere.roundId, elsewhere.request, elsewhere.commitments[0])
    ).toThrowError(/iss mismatch on node 1/);
  });
});

describe("sign: the access token and the refresh token", () => {
  it("signs both tokens, with claims read out of the assertion", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-sign",
    });

    const now = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const { access_token, refresh_token, shares, refreshShares } = signTokens(
      nodes,
      assertion,
      createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT),
      { iat: now, exp: now + 3600, jti }
    );

    // Both sets of shares come back in the clear, as 64 hex digits.
    expect(shares.every((z) => /^[0-9a-f]{64}$/.test(z))).toBe(true);
    expect(refreshShares.every((z) => /^[0-9a-f]{64}$/.test(z))).toBe(true);
    expect(shares).not.toEqual(refreshShares);

    expect(verifyToken(access_token)).toBe(true);
    expect(decodeJwt(access_token).header).toEqual({
      alg: "EdDSA",
      typ: "at+jwt",
      kid: "pasta-group-key-1",
    });
    expect(decodeJwt(access_token).payload).toEqual({
      iss: TEST_ISSUER,
      sub: ALICE_SUB,
      aud: CLIENT_ID,
      scope: SCOPE,
      cnf: { jkt: round.claims.cnfJkt },
      iat: now,
      exp: now + 3600,
      jti,
    });

    expect(verifyToken(refresh_token)).toBe(true);
    expect(decodeJwt(refresh_token).header).toEqual({
      alg: "EdDSA",
      typ: "refresh+jwt",
      kid: "pasta-group-key-1",
    });
    expect(decodeJwt(refresh_token).payload).toEqual({
      iss: TEST_ISSUER,
      sub: ALICE_SUB,
      client_id: CLIENT_ID,
      scope: SCOPE,
      cnf: { jkt: round.claims.cnfJkt },
      iat: now,
      exp: now + 86400 * 30,
    });
  });

  it("refuses to sign both tokens under one FROST round", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-one-round",
    });
    const now = Math.floor(Date.now() / 1000);

    // Two messages under one nonce pair would leak the key share.
    expect(() =>
      signTokens(
        [nodes[0]],
        assertion,
        createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT),
        { iat: now, exp: now + 3600, jti: crypto.randomUUID() },
        { sameRound: true }
      )
    ).toThrowError(/two different rounds/);
  });

  it("spends a refresh token the same way, and rotates it", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-refresh",
    });
    const now = Math.floor(Date.now() / 1000);
    const proof = () => createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT);

    const first = signTokens(nodes, assertion, proof(), {
      iat: now,
      exp: now + 3600,
      jti: crypto.randomUUID(),
    });

    const second = signTokens(
      nodes,
      first.refresh_token,
      proof(),
      { iat: now, exp: now + 900, jti: crypto.randomUUID() },
      { grant: "refresh_token" }
    );

    expect(verifyToken(second.access_token)).toBe(true);
    expect(verifyToken(second.refresh_token)).toBe(true);
    expect(decodeJwt(second.access_token).payload).toMatchObject({
      sub: ALICE_SUB,
      aud: CLIENT_ID,
      scope: SCOPE,
      cnf: { jkt: round.claims.cnfJkt },
      exp: now + 900,
    });
    // Rotated: a new refresh token comes back, and the old one still works, because
    // invalidating it would need state the node deliberately does not keep.
    expect(decodeJwt(second.refresh_token).header.typ).toBe("refresh+jwt");
    const third = signTokens(
      nodes,
      first.refresh_token,
      proof(),
      { iat: now, exp: now + 900, jti: crypto.randomUUID() },
      { grant: "refresh_token" }
    );
    expect(verifyToken(third.access_token)).toBe(true);
  });

  it("refuses a refresh token that is tampered with, expired, or of the wrong type", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-refresh-bad",
    });
    const now = Math.floor(Date.now() / 1000);
    const claims = () => ({ iat: now, exp: now + 3600, jti: crypto.randomUUID() });
    const proof = () => createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT);
    const refresh = (token: string, options = {}) =>
      signTokens(nodes, token, proof(), claims(), { grant: "refresh_token", ...options });

    const { access_token, refresh_token } = signTokens(nodes, assertion, proof(), claims());

    const [h, p, sig] = refresh_token.split(".");
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    payload.scope = "admin";
    const forged = assembleJwt(h, base64UrlEncode(JSON.stringify(payload)), base64UrlDecode(sig));
    expect(() => refresh(forged)).toThrowError(
      /rejected refresh_token: Invalid Ed25519 signature/
    );

    // An access token is not a refresh token, and neither is the assertion.
    expect(() => refresh(access_token)).toThrowError(/typ at\+jwt is not refresh\+jwt/);
    expect(() => refresh(assertion)).toThrowError(/typ JWT is not refresh\+jwt/);

    // A proof from another key does not match the refresh token's cnf.jkt.
    expect(() =>
      signTokens(
        nodes,
        refresh_token,
        createDPoPProof(newDPoPKeyPair().keyPair, "POST", TOKEN_ENDPOINT),
        claims(),
        { grant: "refresh_token" }
      )
    ).toThrowError(/thumbprint mismatch/);

    // And the window really closes: 31 days on, the same refresh token is expired.
    try {
      vi.useFakeTimers({ now: Date.now() + 31 * 86400 * 1000 });
      const later = Math.floor(Date.now() / 1000);
      expect(() =>
        signTokens(
          nodes,
          refresh_token,
          createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT),
          { iat: later, exp: later + 3600, jti: crypto.randomUUID() },
          { grant: "refresh_token" }
        )
      ).toThrowError(/rejected refresh_token: Token expired/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("caps the refresh token lifetime the gateway may ask for", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-refresh-exp",
    });
    const now = Math.floor(Date.now() / 1000);
    const proof = () => createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT);

    const short = signTokens(
      nodes,
      assertion,
      proof(),
      { iat: now, exp: now + 3600, jti: crypto.randomUUID() },
      { refreshExp: now + 600 }
    );
    expect(verifyToken(short.refresh_token)).toBe(true);
    expect(decodeJwt(short.refresh_token).payload.exp).toBe(now + 600);

    expect(() =>
      signTokens(
        nodes,
        assertion,
        proof(),
        { iat: now, exp: now + 3600, jti: crypto.randomUUID() },
        { refreshExp: now + 41 * 86400 }
      )
    ).toThrowError(/Refresh token lifetime \d+s out of range/);
  });

  it("refuses an assertion that is tampered with, expired, or of the wrong type", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-bad-assertion",
    });
    const now = Math.floor(Date.now() / 1000);
    const claims = () => ({ iat: now, exp: now + 3600, jti: crypto.randomUUID() });
    const proof = () => createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT);

    const [h, p, sig] = assertion.split(".");
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    payload.sub = "usr_bob_67890";
    const forged = assembleJwt(h, base64UrlEncode(JSON.stringify(payload)), base64UrlDecode(sig));
    expect(() => signTokens([nodes[0]], forged, proof(), claims())).toThrowError(
      /rejected assertion: Invalid Ed25519 signature/
    );

    // Nothing at all is a 400 too, and so is an access token presented as an assertion.
    expect(() => signTokens([nodes[0]], "a.b.c", proof(), claims())).toThrowError(
      /rejected assertion/
    );

    const { access_token } = signTokens(nodes, assertion, proof(), claims());
    expect(() => signTokens([nodes[0]], access_token, proof(), claims())).toThrowError(
      /typ at\+jwt is not JWT/
    );

    // And the 30-second window really closes: 40 seconds later the same assertion, with a
    // proof and claims that are themselves fresh, is refused as expired.
    const stale = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-stale",
    });
    try {
      vi.useFakeTimers({ now: Date.now() + 40_000 });
      const later = Math.floor(Date.now() / 1000);
      expect(() =>
        signTokens(
          [nodes[0]],
          stale.assertion,
          createDPoPProof(stale.round.dpop.keyPair, "POST", TOKEN_ENDPOINT),
          { iat: later, exp: later + 3600, jti: crypto.randomUUID() }
        )
      ).toThrowError(/rejected assertion: Token expired/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("verifies the DPoP proof against the assertion's own cnf.jkt", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-dpop",
    });
    const now = Math.floor(Date.now() / 1000);
    const claims = () => ({ iat: now, exp: now + 3600, jti: crypto.randomUUID() });

    // A proof bound to another URL, one signed by another key, one for another method.
    expect(() =>
      signTokens(
        [nodes[0]],
        assertion,
        createDPoPProof(round.dpop.keyPair, "POST", "http://evil.test/token"),
        claims()
      )
    ).toThrowError(/rejected DPoP proof: htu mismatch/);

    expect(() =>
      signTokens(
        [nodes[0]],
        assertion,
        createDPoPProof(newDPoPKeyPair().keyPair, "POST", TOKEN_ENDPOINT),
        claims()
      )
    ).toThrowError(/thumbprint mismatch/);

    expect(() =>
      signTokens(
        [nodes[0]],
        assertion,
        createDPoPProof(round.dpop.keyPair, "GET", TOKEN_ENDPOINT),
        claims()
      )
    ).toThrowError(/htm mismatch/);

    // The same proof twice is deliberately allowed: the node keeps no jti list, and the
    // token that comes back is bound to a key the replayer does not have.
    const proof = createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT);
    expect(signTokens([nodes[0]], assertion, proof, claims()).shares).toHaveLength(1);
    expect(signTokens([nodes[0]], assertion, proof, claims()).shares).toHaveLength(1);
  });

  it("range-checks the claims the gateway pins", () => {
    const nodes = freshNodes();
    const { round, assertion } = assertionFor(nodes, {
      username: USERNAME,
      password: PASSWORD,
      nonce: "c-claims",
    });
    const now = Math.floor(Date.now() / 1000);
    const proof = () => createDPoPProof(round.dpop.keyPair, "POST", TOKEN_ENDPOINT);

    expect(() =>
      signTokens([nodes[0]], assertion, proof(), {
        iat: now,
        exp: now + 3601,
        jti: crypto.randomUUID(),
      })
    ).toThrowError(/Access token lifetime 3601s out of range/);

    expect(() =>
      signTokens([nodes[0]], assertion, proof(), {
        iat: now - 3600,
        exp: now,
        jti: crypto.randomUUID(),
      })
    ).toThrowError(/iat is outside the ±60s window/);

    expect(() =>
      signTokens([nodes[0]], assertion, proof(), { iat: now, exp: now, jti: "x" })
    ).toThrowError(/Access token lifetime 0s out of range/);
  });
});
