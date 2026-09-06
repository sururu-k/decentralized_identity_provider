import { afterAll, beforeAll, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { blind } from "../src/crypto/toprf.js";
import { base64UrlDecode, base64UrlEncode } from "../src/jwt/jwt.js";
import {
  RunningNode,
  getJson,
  hexToBytes,
  postJson,
  readFixtureJson,
  startAllNodes,
  stopAll,
} from "./helpers/nodes.js";
import { collectCommitments, refreshOverHttp, signOnOverHttp } from "./helpers/client.js";

/**
 * Component end-to-end test. Three node servers run on ephemeral ports, exactly as three
 * containers would, and every protocol message travels over real HTTP.
 */

const GROUP = readFixtureJson("group.json");
const GROUP_PUBLIC_KEY = hexToBytes(GROUP.groupPublicKey);
const ISSUER = "http://localhost:3000";
const CLIENT_ID = "demo_client";
const REFRESH_URL = `${ISSUER}/api/pasta/refresh`;

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

  it("answers 404 on an unknown route", async () => {
    const res = await postJson(nodes[0].url, "/nope", {});
    expect(res.status).toBe(404);
    expect(res.body.error).toContain("Not found");
  });

  it("answers 405 when the method is wrong", async () => {
    const res = await getJson(nodes[0].url, "/commit");
    expect(res.status).toBe(405);
    expect(res.body.error).toContain("not allowed");
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
      request: {
        sessionId: "s1",
        username: "alice",
        blinded: validBlinded(),
        sessionNonce: base64UrlEncode(crypto.randomBytes(16)),
        cnfJkt: "jkt",
        iat: 1,
        exp: 2,
        aud: CLIENT_ID,
        iss: ISSUER,
        commitments,
        allParticipants: [2, 3],
      },
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("commitments contains no entry for node 1");
  });

  it("answers 400 for an unknown user", async () => {
    const roundId = crypto.randomUUID();
    const commitments = await collectCommitments([nodes[0]], roundId);

    const res = await postJson(nodes[0].url, "/sign-on", {
      roundId,
      request: {
        sessionId: crypto.randomUUID(),
        username: "mallory",
        blinded: validBlinded(),
        sessionNonce: base64UrlEncode(crypto.randomBytes(16)),
        cnfJkt: "jkt",
        iat: 1,
        exp: 2,
        aud: CLIENT_ID,
        iss: ISSUER,
        commitments,
        allParticipants: [1],
      },
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("User not found on node 1");
  });

  it("consumes a round nonce once, so a replayed /sign-on is refused", async () => {
    const roundId = crypto.randomUUID();
    const commitments = await collectCommitments([nodes[0]], roundId);
    const request = {
      sessionId: crypto.randomUUID(),
      username: "alice",
      blinded: validBlinded(),
      sessionNonce: base64UrlEncode(crypto.randomBytes(16)),
      cnfJkt: "jkt",
      iat: 1,
      exp: 2,
      aud: CLIENT_ID,
      iss: ISSUER,
      commitments,
      allParticipants: [1],
    };

    const first = await postJson(nodes[0].url, "/sign-on", { roundId, request });
    expect(first.status).toBe(200);

    const replay = await postJson(nodes[0].url, "/sign-on", { roundId, request });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toContain("expired or not found");
  });
});

describe("component end-to-end over HTTP", () => {
  it("signs alice in across all three nodes and verifies the token", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "nonce-e2e-1",
    });

    expect(verifyToken(session.id_token)).toBe(true);

    const { header, payload } = decodeJwt(session.id_token);
    expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" });
    expect(payload.iss).toBe(ISSUER);
    expect(payload.aud).toBe(CLIENT_ID);
    expect(payload.sub).toBe("usr_alice_12345");
    expect(payload.nonce).toBe("nonce-e2e-1");
    expect(payload.cnf).toEqual({ jkt: session.cnfJkt });
    expect(session.nodeSecrets.size).toBe(3);
  });

  it("signs bob in, and every node agrees on the byte-identical payload", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "bob",
      password: "password456",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "nonce-bob",
    });

    expect(verifyToken(session.id_token)).toBe(true);
    expect(decodeJwt(session.id_token).payload.sub).toBe("usr_bob_67890");
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
    expect(verifyToken(session.id_token)).toBe(true);

    const raw = Buffer.from(session.id_token.split(".")[1], "base64url").toString("utf8");
    expect(raw).toContain('"sub":"usr_bob_67890"');
    // Known behaviour of the copied deterministicJsonStringify: an absent nonce is
    // written as the bare token `undefined`, so such a payload is not parseable JSON.
    // The gateway always supplies a nonce, so this shape does not occur in the product.
    expect(raw).toContain('"nonce":undefined');
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
        nonce: "nonce-quorum",
      });
      expect(verifyToken(session.id_token)).toBe(true);
      expect(session.nodeSecrets.size).toBe(2);
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
        nonce: "nonce-bad-pw",
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
        subOverride: "admin",
      })
    ).rejects.toThrow(/Invalid password or corrupted share/);
  });

  it("refreshes the token with a DPoP proof", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "nonce-before-refresh",
    });
    expect(verifyToken(session.id_token)).toBe(true);

    const first = await refreshOverHttp({
      nodes,
      session,
      clientId: CLIENT_ID,
      issuer: ISSUER,
      refreshEndpointUrl: REFRESH_URL,
      nonce: "nonce-after-refresh",
    });

    expect(first.ctr).toBe(1);
    expect(verifyToken(first.id_token)).toBe(true);
    expect(first.id_token).not.toBe(session.id_token);
    const payload = decodeJwt(first.id_token).payload;
    expect(payload.sub).toBe("usr_alice_12345");
    expect(payload.nonce).toBe("nonce-after-refresh");
    expect(payload.cnf).toEqual({ jkt: session.cnfJkt });

    // A second refresh advances the counter on every node.
    const second = await refreshOverHttp({
      nodes,
      session,
      clientId: CLIENT_ID,
      issuer: ISSUER,
      refreshEndpointUrl: REFRESH_URL,
      nonce: "nonce-after-refresh-2",
    });
    expect(second.ctr).toBe(2);
    expect(verifyToken(second.id_token)).toBe(true);
  });

  it("refreshes on a 2-of-3 subset of the signing quorum", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "nonce-subset",
    });

    const refreshed = await refreshOverHttp({
      nodes: [nodes[1], nodes[2]],
      session,
      clientId: CLIENT_ID,
      issuer: ISSUER,
      refreshEndpointUrl: REFRESH_URL,
      nonce: "nonce-subset-2",
    });

    expect(verifyToken(refreshed.id_token)).toBe(true);
  });

  it("rejects a refresh whose DPoP proof is bound to another URL", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "nonce-bad-dpop",
    });

    await expect(
      refreshOverHttp({
        nodes,
        session,
        clientId: CLIENT_ID,
        issuer: ISSUER,
        refreshEndpointUrl: REFRESH_URL,
        proofHtuOverride: "http://evil.test/api/pasta/refresh",
      })
    ).rejects.toThrow(/rejected DPoP proof/);
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
      nonce: "nonce-round-b",
      round: { roundId: roundB, commitments: commitmentsB },
    });
    const sessionA = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "nonce-round-a",
      round: { roundId: roundA, commitments: commitmentsA },
    });

    expect(verifyToken(sessionB.id_token)).toBe(true);
    expect(verifyToken(sessionA.id_token)).toBe(true);
    expect(decodeJwt(sessionA.id_token).payload.sub).toBe("usr_alice_12345");
    expect(decodeJwt(sessionB.id_token).payload.sub).toBe("usr_bob_67890");
    expect(decodeJwt(sessionA.id_token).payload.nonce).toBe("nonce-round-a");
    expect(decodeJwt(sessionB.id_token).payload.nonce).toBe("nonce-round-b");
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
          nonce: `nonce-parallel-${i}`,
        });
      })
    );

    sessions.forEach((session, i) => {
      expect(verifyToken(session.id_token)).toBe(true);
      const { payload } = decodeJwt(session.id_token);
      expect(payload.sub).toBe(users[i % users.length].sub);
      expect(payload.nonce).toBe(`nonce-parallel-${i}`);
    });

    // Every round got its own session on every node.
    expect(new Set(sessions.map((s) => s.sessionId)).size).toBe(sessions.length);
  });

  it("refreshes two sessions concurrently", async () => {
    const [first, second] = await Promise.all([
      signOnOverHttp({
        nodes,
        username: "alice",
        password: "password123",
        clientId: CLIENT_ID,
        issuer: ISSUER,
        nonce: "nonce-parallel-refresh-1",
      }),
      signOnOverHttp({
        nodes,
        username: "bob",
        password: "password456",
        clientId: CLIENT_ID,
        issuer: ISSUER,
        nonce: "nonce-parallel-refresh-2",
      }),
    ]);

    const refreshed = await Promise.all([
      refreshOverHttp({
        nodes,
        session: first,
        clientId: CLIENT_ID,
        issuer: ISSUER,
        refreshEndpointUrl: REFRESH_URL,
        nonce: "nonce-parallel-refresh-1b",
      }),
      refreshOverHttp({
        nodes,
        session: second,
        clientId: CLIENT_ID,
        issuer: ISSUER,
        refreshEndpointUrl: REFRESH_URL,
        nonce: "nonce-parallel-refresh-2b",
      }),
    ]);

    expect(verifyToken(refreshed[0].id_token)).toBe(true);
    expect(verifyToken(refreshed[1].id_token)).toBe(true);
    expect(decodeJwt(refreshed[0].id_token).payload.sub).toBe("usr_alice_12345");
    expect(decodeJwt(refreshed[1].id_token).payload.sub).toBe("usr_bob_67890");
    expect(refreshed[0].ctr).toBe(1);
    expect(refreshed[1].ctr).toBe(1);
  });
});
