import { afterAll, beforeAll, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { blind } from "../src/crypto/toprf.js";
import { createDPoPProof } from "../src/client-sdk/dpop.js";
import { aggregateSignatureShares, computeGroupCommitment } from "../src/crypto/frost.js";
import { commitmentFromWire } from "../src/wire.js";
import { assembleJwt, base64UrlDecode, base64UrlEncode } from "../src/jwt/jwt.js";
import {
  RunningNode,
  TEST_ISSUER,
  getJson,
  hexToBytes,
  postJson,
  readFixtureJson,
  startAllNodes,
  stopAll,
} from "./helpers/nodes.js";
import {
  buildAccessTokenSigningInput,
  collectCommitments,
  newDPoPKeyPair,
  prepareSign,
  signOnOverHttp,
  signOverHttp,
} from "./helpers/client.js";

/**
 * Component end-to-end test. Three node servers run on ephemeral ports, exactly as three
 * containers would, and every protocol message travels over real HTTP: `/commit` and
 * `/sign-on` for the assertion, which is the authorization code, then `/commit` and
 * `/sign` to turn that assertion into an access token (docs/container-split.md section
 * 14). The nodes keep no session between the two halves.
 */

const GROUP = readFixtureJson("group.json");
const GROUP_PUBLIC_KEY = hexToBytes(GROUP.groupPublicKey);
const ISSUER = TEST_ISSUER;
const CLIENT_ID = "demo_client";
const SCOPE = "openid profile";
const TOKEN_ENDPOINT = `${ISSUER}/token`;

let nodes: RunningNode[];

beforeAll(async () => {
  nodes = await startAllNodes();
});

afterAll(async () => {
  await stopAll(nodes);
});

/** A real blinded TOPRF point, so requests get past the node's point decoding. */
function validBlinded(): string {
  return base64UrlEncode(blind("password123").blinded.toRawBytes());
}

/** A literal `/sign-on` request body of the shape the gateway sends. */
function signOnBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    sessionId: crypto.randomUUID(),
    username: "alice",
    blinded: validBlinded(),
    sessionNonce: base64UrlEncode(crypto.randomBytes(16)),
    cnfJkt: "jkt",
    clientId: CLIENT_ID,
    scope: SCOPE,
    nonce: "c",
    iat: now,
    exp: now + 30,
    iss: ISSUER,
    ...overrides,
  };
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

/** A sign-on whose assertion is ready to be spent at `/sign`. */
function liveSession(overrides: Partial<Parameters<typeof signOnOverHttp>[0]> = {}) {
  return signOnOverHttp({
    nodes,
    username: "alice",
    password: "password123",
    clientId: CLIENT_ID,
    issuer: ISSUER,
    nonce: `c-${crypto.randomUUID()}`,
    ...overrides,
  });
}

describe("node HTTP API", () => {
  it("reports health with its node id and group public key", async () => {
    for (const n of nodes) {
      const res = await getJson(n.url, "/health");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        status: "ok",
        nodeId: n.nodeId,
        groupPublicKey: base64UrlEncode(GROUP_PUBLIC_KEY),
      });
    }
    expect(nodes.map((n) => n.nodeId).sort()).toEqual([1, 2, 3]);
  });

  it("returns a base64url commitment from /commit", async () => {
    const res = await postJson(nodes[0].url, "/commit", { roundId: crypto.randomUUID() });
    expect(res.status).toBe(200);
    expect(res.body.nodeId).toBe(1);
    expect(res.body.D).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(res.body.E).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(base64UrlDecode(res.body.D)).toHaveLength(32);
  });

  it("answers 404 on an unknown route, /refresh and /authenticate included", async () => {
    const res = await postJson(nodes[0].url, "/nope", {});
    expect(res.status).toBe(404);
    expect(res.body.error).toContain("Not found");

    // Both endpoints of the earlier designs are gone: there is no refresh grant on the
    // node, and no session to promote (section 14).
    for (const gone of ["/refresh", "/authenticate"]) {
      const answer = await postJson(nodes[0].url, gone, { roundId: "r" });
      expect(answer.status, gone).toBe(404);
      expect(answer.body.error).toContain("Not found");
    }
  });

  it("answers 405 when the method is wrong", async () => {
    for (const path of ["/commit", "/sign-on", "/sign"]) {
      const res = await getJson(nodes[0].url, path);
      expect(res.status).toBe(405);
      expect(res.body.error).toContain("not allowed");
    }
  });

  it("answers 400 on a body that is not JSON", async () => {
    const res = await postJson(nodes[0].url, "/commit", null, { raw: "{not json" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Request body is not valid JSON");
  });

  it("answers 400 when a required field is missing", async () => {
    const res = await postJson(nodes[0].url, "/commit", {});
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("roundId");

    const noClientId = await postJson(nodes[0].url, "/sign-on", {
      roundId: crypto.randomUUID(),
      request: { ...signOnBody(), clientId: undefined, commitments: [], allParticipants: [1] },
    });
    expect(noClientId.status).toBe(400);
    expect(noClientId.body.error).toContain("clientId");

    const noAssertion = await postJson(nodes[0].url, "/sign", {
      roundId: "r",
      refreshRoundId: "r2",
      request: {
        grant: "authorization_code",
        dpopProof: "a.b.c",
        claims: { iat: 1, exp: 2, jti: "j" },
        commitments: [],
        refreshCommitments: [],
        allParticipants: [1],
      },
    });
    expect(noAssertion.status).toBe(400);
    expect(noAssertion.body.error).toContain("assertion");

    const oneRound = await postJson(nodes[0].url, "/sign", { roundId: "r", refreshRoundId: "r" });
    expect(oneRound.status).toBe(400);
    expect(oneRound.body.error).toContain("refreshRoundId must differ");
  });

  it("answers 413 on an oversized body", async () => {
    const res = await postJson(nodes[0].url, "/commit", null, {
      raw: JSON.stringify({ roundId: "x".repeat(2 * 1024 * 1024) }),
    });
    expect(res.status).toBe(413);
    expect(res.body.error).toContain("exceeds");
  });

  it("answers 400 when the commitment set has no entry for this node", async () => {
    const roundId = crypto.randomUUID();
    const commitments = await collectCommitments([nodes[1], nodes[2]], roundId);
    await postJson(nodes[0].url, "/commit", { roundId });

    const res = await postJson(nodes[0].url, "/sign-on", {
      roundId,
      request: { ...signOnBody(), commitments, allParticipants: [2, 3] },
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("commitments contains no entry for node 1");
  });

  it("answers 400 for an unknown user", async () => {
    const roundId = crypto.randomUUID();
    const commitments = await collectCommitments([nodes[0]], roundId);

    const res = await postJson(nodes[0].url, "/sign-on", {
      roundId,
      request: { ...signOnBody({ username: "mallory" }), commitments, allParticipants: [1] },
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("User not found on node 1");
  });

  it("answers 400 for an assertion lifetime over 30 seconds", async () => {
    const roundId = crypto.randomUUID();
    const commitments = await collectCommitments([nodes[0]], roundId);
    const now = Math.floor(Date.now() / 1000);

    const res = await postJson(nodes[0].url, "/sign-on", {
      roundId,
      request: {
        ...signOnBody({ iat: now, exp: now + 120 }),
        commitments,
        allParticipants: [1],
      },
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Assertion lifetime 120s out of range");
  });

  it("consumes a round nonce once, so a replayed /sign-on is refused", async () => {
    const roundId = crypto.randomUUID();
    const commitments = await collectCommitments([nodes[0]], roundId);
    const request = { ...signOnBody(), commitments, allParticipants: [1] };

    const first = await postJson(nodes[0].url, "/sign-on", { roundId, request });
    expect(first.status).toBe(200);

    const replay = await postJson(nodes[0].url, "/sign-on", { roundId, request });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toContain("expired or not found");
  });
});

describe("assertion over HTTP", () => {
  it("signs alice in across all three nodes and verifies the assertion", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "c-e2e-1",
    });

    expect(verifyToken(session.assertion)).toBe(true);

    const { header, payload } = decodeJwt(session.assertion);
    expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" });
    expect(payload.iss).toBe(ISSUER);
    expect(payload.aud).toBe(ISSUER);
    expect(payload.sub).toBe("usr_alice_12345");
    expect(payload.nonce).toBe("c-e2e-1");
    expect(payload.cnf).toEqual({ jkt: session.cnfJkt });
  });

  it("signs bob in, and every node agrees on the byte-identical payload", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "bob",
      password: "password456",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "c-bob",
    });

    expect(verifyToken(session.assertion)).toBe(true);
    expect(decodeJwt(session.assertion).payload.sub).toBe("usr_bob_67890");
  });

  it("still agrees on the payload when the request carries no nonce", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "bob",
      password: "password456",
      clientId: CLIENT_ID,
      issuer: ISSUER,
    });

    // The signature is valid: node and client serialize the same bytes either way.
    expect(verifyToken(session.assertion)).toBe(true);

    const raw = Buffer.from(session.assertion.split(".")[1], "base64url").toString("utf8");
    expect(raw).toContain('"sub":"usr_bob_67890"');
    // Known behaviour of the copied deterministicJsonStringify: an absent nonce is
    // written as the bare token `undefined`, so such a payload is not parseable JSON and
    // /sign cannot accept the assertion. The gateway always sends the challenge as
    // `nonce`.
    expect(raw).toContain('"nonce":undefined');
    const attempt = await prepareSign({ nodes: [nodes[0]], session });
    const res = await postJson(nodes[0].url, "/sign", {
      roundId: attempt.accessRoundId,
      refreshRoundId: attempt.refreshRoundId,
      request: attempt.request,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("rejected assertion");
  });

  it("succeeds with a 2-of-3 quorum", async () => {
    for (const quorum of [
      [nodes[0], nodes[1]],
      [nodes[1], nodes[2]],
      [nodes[0], nodes[2]],
    ]) {
      const session = await signOnOverHttp({
        nodes: quorum,
        username: "alice",
        password: "password123",
        clientId: CLIENT_ID,
        issuer: ISSUER,
        nonce: "c-quorum",
      });
      expect(verifyToken(session.assertion)).toBe(true);
    }
  });

  it("fails to decrypt with the wrong password", async () => {
    await expect(
      signOnOverHttp({
        nodes,
        username: "alice",
        password: "WRONG-password",
        clientId: CLIENT_ID,
        issuer: ISSUER,
        nonce: "c-bad-pw",
      })
    ).rejects.toThrow(/Invalid password or corrupted share/);
  });

  it("fails to decrypt when the client assumes a spoofed sub", async () => {
    await expect(
      signOnOverHttp({
        nodes,
        username: "alice",
        password: "password123",
        clientId: CLIENT_ID,
        issuer: ISSUER,
        nonce: "c-spoof",
        subOverride: "admin",
      })
    ).rejects.toThrow(/Invalid password or corrupted share/);
  });
});

describe("access token over HTTP", () => {
  it("refuses a tampered assertion at /sign", async () => {
    const session = await liveSession();

    const [h, p, sig] = session.assertion.split(".");
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    payload.sub = "usr_bob_67890";
    const forged = assembleJwt(h, base64UrlEncode(JSON.stringify(payload)), base64UrlDecode(sig));

    const attempt = await prepareSign({ nodes: [nodes[0]], session, assertionOverride: forged });
    const res = await postJson(nodes[0].url, "/sign", {
      roundId: attempt.accessRoundId,
      refreshRoundId: attempt.refreshRoundId,
      request: attempt.request,
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Invalid Ed25519 signature");
  });

  it("returns plaintext shares that aggregate into an access token and a refresh token", async () => {
    const session = await liveSession();
    const { access_token, refresh_token, claims, refreshClaims, shares, refreshShares } =
      await signOverHttp({ nodes, session });

    expect(shares).toHaveLength(3);
    expect(refreshShares).toHaveLength(3);
    expect(shares.every((z) => /^[0-9a-f]{64}$/.test(z))).toBe(true);
    expect(refreshShares.every((z) => /^[0-9a-f]{64}$/.test(z))).toBe(true);

    expect(verifyToken(refresh_token)).toBe(true);
    expect(decodeJwt(refresh_token).header).toEqual({
      alg: "EdDSA",
      typ: "refresh+jwt",
      kid: "pasta-group-key-1",
    });
    expect(decodeJwt(refresh_token).payload).toEqual({
      iss: ISSUER,
      sub: "usr_alice_12345",
      client_id: CLIENT_ID,
      scope: SCOPE,
      cnf: { jkt: session.cnfJkt },
      iat: refreshClaims.iat,
      exp: refreshClaims.iat + 86400 * 30,
    });

    expect(verifyToken(access_token)).toBe(true);
    const { header, payload } = decodeJwt(access_token);
    expect(header).toEqual({ alg: "EdDSA", typ: "at+jwt", kid: "pasta-group-key-1" });
    expect(payload).toEqual({
      iss: ISSUER,
      sub: "usr_alice_12345",
      aud: CLIENT_ID,
      scope: SCOPE,
      cnf: { jkt: session.cnfJkt },
      iat: claims.iat,
      exp: claims.exp,
      jti: claims.jti,
    });
    expect(payload.exp - payload.iat).toBe(3600);
  });

  it("signs twice against the same assertion, which is what a refresh grant does", async () => {
    const session = await liveSession();
    const first = await signOverHttp({ nodes, session });
    const second = await signOverHttp({ nodes, session });

    expect(verifyToken(first.access_token)).toBe(true);
    expect(verifyToken(second.access_token)).toBe(true);
    expect(second.access_token).not.toBe(first.access_token);
    expect(decodeJwt(second.access_token).payload.jti).not.toBe(
      decodeJwt(first.access_token).payload.jti
    );
  });

  it("signs on a 2-of-3 subset of the nodes that saw the sign-on", async () => {
    const session = await liveSession();
    const { access_token } = await signOverHttp({ nodes: [nodes[1], nodes[2]], session });
    expect(verifyToken(access_token)).toBe(true);
  });

  it("refuses another key, another URL and an over-long lifetime, but not a proof reuse", async () => {
    const session = await liveSession();

    // The same proof twice is fine: no jti is recorded, and the token that comes back is
    // bound to a key the replayer does not hold.
    const proof = createDPoPProof(session.dpopKeyPair, "POST", TOKEN_ENDPOINT);
    const first = await signOverHttp({ nodes, session, dpopProofOverride: proof });
    const again = await signOverHttp({ nodes, session, dpopProofOverride: proof });
    expect(verifyToken(first.access_token)).toBe(true);
    expect(verifyToken(again.access_token)).toBe(true);

    const cases: Array<[string, Awaited<ReturnType<typeof prepareSign>>]> = [
      ["thumbprint mismatch", await prepareSign({ nodes, session, keyPairOverride: newDPoPKeyPair().keyPair })],
      ["htu mismatch", await prepareSign({ nodes, session, proofHtuOverride: "http://evil.test/token" })],
      ["Access token lifetime 3601s out of range", await prepareSign({ nodes, session, lifetimeSeconds: 3601 })],
    ];

    for (const [reason, attempt] of cases) {
      const res = await postJson(nodes[0].url, "/sign", {
        roundId: attempt.accessRoundId,
        refreshRoundId: attempt.refreshRoundId,
        request: attempt.request,
      });
      expect(res.status, reason).toBe(400);
      expect(res.body.error).toContain(reason);
    }
  });

  it("takes sub, aud, scope and cnf.jkt from the assertion, not from the caller", async () => {
    const session = await liveSession();
    const attempt = await prepareSign({ nodes, session });

    // The gateway tries to widen the token by adding claims next to the assertion.
    const res = await postJson(nodes[0].url, "/sign", {
      roundId: attempt.accessRoundId,
      refreshRoundId: attempt.refreshRoundId,
      request: {
        ...attempt.request,
        sub: "admin",
        aud: "another_client",
        scope: "admin",
        cnfJkt: newDPoPKeyPair().cnfJkt,
      },
    });
    expect(res.status).toBe(200);

    // Node 1 signed the assertion's own claims, so its share fits only the payload the
    // client rebuilds from what the assertion says.
    const rest = await Promise.all(
      [nodes[1], nodes[2]].map((n) =>
        postJson(n.url, "/sign", {
          roundId: attempt.accessRoundId,
          refreshRoundId: attempt.refreshRoundId,
          request: attempt.request,
        })
      )
    );
    expect(rest.every((r) => r.status === 200)).toBe(true);

    const shares = [res.body, ...rest.map((r) => r.body)].map((b) => BigInt("0x" + b.at.z_i));
    const { signingInput, headerB64, payloadB64 } = buildAccessTokenSigningInput(attempt.atClaims);
    const R = computeGroupCommitment(
      signingInput,
      attempt.commitments.map((c) => commitmentFromWire(c))
    );
    const token = assembleJwt(headerB64, payloadB64, aggregateSignatureShares(R, shares));

    expect(verifyToken(token)).toBe(true);
    const { payload } = decodeJwt(token);
    expect(payload.sub).toBe("usr_alice_12345");
    expect(payload.aud).toBe(CLIENT_ID);
    expect(payload.scope).toBe(SCOPE);
    expect(payload.cnf).toEqual({ jkt: session.cnfJkt });
  });
});

describe("refresh grant over HTTP", () => {
  it("spends the refresh token for a new pair, and refuses a foreign key or a forgery", async () => {
    const session = await liveSession();
    const first = await signOverHttp({ nodes, session });
    expect(decodeJwt(first.refresh_token).header.typ).toBe("refresh+jwt");

    // Same DPoP key, refresh_token grant: a new access token and a new refresh token.
    const second = await signOverHttp({
      nodes,
      session,
      grant: "refresh_token",
      refreshToken: first.refresh_token,
      lifetimeSeconds: 900,
    });
    expect(verifyToken(second.access_token)).toBe(true);
    expect(verifyToken(second.refresh_token)).toBe(true);
    expect(second.refresh_token).not.toBe(first.refresh_token);
    expect(decodeJwt(second.access_token).payload).toMatchObject({
      sub: "usr_alice_12345",
      aud: CLIENT_ID,
      scope: SCOPE,
      cnf: { jkt: session.cnfJkt },
    });
    expect(decodeJwt(second.access_token).payload.exp - decodeJwt(second.access_token).payload.iat)
      .toBe(900);

    // A proof from another key does not match the refresh token's cnf.jkt.
    const foreign = await prepareSign({
      nodes,
      session,
      grant: "refresh_token",
      refreshToken: first.refresh_token,
      keyPairOverride: newDPoPKeyPair().keyPair,
    });
    const foreignRes = await postJson(nodes[0].url, "/sign", {
      roundId: foreign.accessRoundId,
      refreshRoundId: foreign.refreshRoundId,
      request: foreign.request,
    });
    expect(foreignRes.status).toBe(400);
    expect(foreignRes.body.error).toContain("thumbprint mismatch");

    // A tampered refresh token, and an access token offered as one.
    const [h, p, sig] = first.refresh_token.split(".");
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    payload.scope = "admin";
    const forged = assembleJwt(h, base64UrlEncode(JSON.stringify(payload)), base64UrlDecode(sig));

    for (const [token, reason] of [
      [forged, "Invalid Ed25519 signature"],
      [first.access_token, "typ at+jwt is not refresh+jwt"],
    ] as const) {
      const attempt = await prepareSign({
        nodes,
        session,
        grant: "refresh_token",
        refreshToken: token,
      });
      const res = await postJson(nodes[0].url, "/sign", {
        roundId: attempt.accessRoundId,
        refreshRoundId: attempt.refreshRoundId,
        request: attempt.request,
      });
      expect(res.status, reason).toBe(400);
      expect(res.body.error).toContain(reason);
    }
  });
});

/**
 * A node keeps its round-1 nonce pairs in a map keyed by `roundId`, and every gateway
 * worker draws its own `roundId`. These tests pin that keying: if two rounds in flight at
 * once could ever hand each other's nonces to round 2, the FROST share would be computed
 * against the wrong commitment and the aggregated signature would simply not verify.
 */
describe("concurrent rounds", () => {
  it("keeps two interleaved rounds apart", async () => {
    const roundA = crypto.randomUUID();
    const roundB = crypto.randomUUID();

    // Both rounds are opened on every node before either one reaches round 2.
    const commitmentsA = await collectCommitments(nodes, roundA);
    const commitmentsB = await collectCommitments(nodes, roundB);
    expect(commitmentsA.map((c) => c.D)).not.toEqual(commitmentsB.map((c) => c.D));

    // Finish the second round first. A node that confused the two would sign under the
    // other round's nonces here.
    const sessionB = await signOnOverHttp({
      nodes,
      username: "bob",
      password: "password456",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "c-round-b",
      round: { roundId: roundB, commitments: commitmentsB },
    });
    const sessionA = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "c-round-a",
      round: { roundId: roundA, commitments: commitmentsA },
    });

    expect(verifyToken(sessionB.assertion)).toBe(true);
    expect(verifyToken(sessionA.assertion)).toBe(true);
    expect(decodeJwt(sessionA.assertion).payload.sub).toBe("usr_alice_12345");
    expect(decodeJwt(sessionB.assertion).payload.sub).toBe("usr_bob_67890");
    expect(decodeJwt(sessionA.assertion).payload.nonce).toBe("c-round-a");
    expect(decodeJwt(sessionB.assertion).payload.nonce).toBe("c-round-b");
  });

  it("signs four rounds in flight at once, over the same three nodes", async () => {
    const users = [
      { username: "alice", password: "password123", sub: "usr_alice_12345" },
      { username: "bob", password: "password456", sub: "usr_bob_67890" },
    ];

    const sessions = await Promise.all(
      Array.from({ length: 4 }, (_, i) => {
        const user = users[i % users.length];
        return signOnOverHttp({
          nodes,
          username: user.username,
          password: user.password,
          clientId: CLIENT_ID,
          issuer: ISSUER,
          nonce: `c-parallel-${i}`,
        });
      })
    );

    sessions.forEach((session, i) => {
      expect(verifyToken(session.assertion)).toBe(true);
      const { payload } = decodeJwt(session.assertion);
      expect(payload.sub).toBe(users[i % users.length].sub);
      expect(payload.nonce).toBe(`c-parallel-${i}`);
    });

    // Every round got its own session on every node.
    expect(new Set(sessions.map((s) => s.sessionId)).size).toBe(sessions.length);
  });

  it("issues access tokens for two assertions concurrently", async () => {
    const [first, second] = await Promise.all([
      liveSession(),
      liveSession({ username: "bob", password: "password456" }),
    ]);

    const tokens = await Promise.all([
      signOverHttp({ nodes, session: first }),
      signOverHttp({ nodes, session: second }),
    ]);

    expect(verifyToken(tokens[0].access_token)).toBe(true);
    expect(verifyToken(tokens[1].access_token)).toBe(true);
    expect(decodeJwt(tokens[0].access_token).payload.sub).toBe("usr_alice_12345");
    expect(decodeJwt(tokens[1].access_token).payload.sub).toBe("usr_bob_67890");
  });
});
