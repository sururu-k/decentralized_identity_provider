import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import type { IdentityNode } from "../src/protocol/node.js";
import { createDPoPProof } from "../src/client-sdk/dpop.js";
import { base64UrlDecode } from "../src/jwt/jwt.js";
import { buildNodeFromFixture, hexToBytes, readFixtureJson } from "./helpers/nodes.js";
import { newDPoPKeyPair } from "./helpers/client.js";
import { aggregateSignOn, runSignOn, startRound } from "./helpers/inproc.js";

/**
 * Node-only properties ported from `tests/pasta_integration.test.ts`. They exercise
 * `IdentityNode` directly, with the gateway's relay role and the client's aggregation
 * role played by the test.
 */

const PASSWORD = "password123";
const USERNAME = "alice";
const ALICE_SUB = "usr_alice_12345";
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

describe("IdentityNode protocol behaviour", () => {
  it("mints a token verifiable under the dealer's group public key", () => {
    const nodes = freshNodes();
    const round = startRound(nodes, { username: USERNAME, password: PASSWORD, nonce: "n1" });
    const responses = runSignOn(nodes, round);

    const { id_token } = aggregateSignOn({ round, responses, password: PASSWORD });

    expect(verifyToken(id_token)).toBe(true);
    const { header, payload } = decodeJwt(id_token);
    expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" });
    expect(payload.sub).toBe(ALICE_SUB);
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
    expect(verifyToken(partial.id_token)).toBe(false);

    const complete = aggregateSignOn({ round, responses, password: PASSWORD });
    expect(verifyToken(complete.id_token)).toBe(true);
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

  it("rejects a refresh for an unknown session", () => {
    const nodes = freshNodes();
    const roundId = crypto.randomUUID();
    const commitment = nodes[0].generateCommitment(roundId);
    const { keyPair } = newDPoPKeyPair();
    const htu = "http://localhost:3000/api/pasta/refresh";

    expect(() =>
      nodes[0].handleRefresh(
        roundId,
        {
          sessionId: "no-such-session",
          dpopProof: createDPoPProof(keyPair, "POST", htu),
          expectedHtu: htu,
          iat: 0,
          exp: 0,
          aud: "demo_client",
          iss: "http://localhost:3000",
          commitments: [{ nodeId: 1, ...commitment }],
          allParticipants: [1],
        },
        commitment
      )
    ).toThrowError(/Session no-such-session not found on node 1/);
  });

  it("verifies the DPoP proof itself on refresh", () => {
    const nodes = freshNodes();
    const dpop = newDPoPKeyPair();
    const round = startRound(nodes, {
      username: USERNAME,
      password: PASSWORD,
      cnfJkt: dpop.cnfJkt,
    });
    runSignOn(nodes, round);

    const htu = "http://localhost:3000/api/pasta/refresh";
    const refreshRoundId = crypto.randomUUID();
    const commitment = nodes[0].generateCommitment(refreshRoundId);

    // Proof signed for a different URL than the node is told to expect.
    const other = newDPoPKeyPair();
    const base = {
      sessionId: round.sessionId,
      expectedHtu: htu,
      iat: 0,
      exp: 0,
      aud: "demo_client",
      iss: "http://localhost:3000",
      commitments: [{ nodeId: 1, ...commitment }],
      allParticipants: [1],
    };

    expect(() =>
      nodes[0].handleRefresh(
        refreshRoundId,
        { ...base, dpopProof: createDPoPProof(dpop.keyPair, "POST", "http://evil.test/refresh") },
        commitment
      )
    ).toThrowError(/rejected DPoP proof/);

    // A proof from a different key does not match the stored cnf.jkt either.
    expect(() =>
      nodes[0].handleRefresh(
        refreshRoundId,
        { ...base, dpopProof: createDPoPProof(other.keyPair, "POST", htu) },
        commitment
      )
    ).toThrowError(/thumbprint mismatch/);
  });
});
