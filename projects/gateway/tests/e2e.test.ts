import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  calculateJwkThumbprint,
  createDPoPProof,
  exportDPoPJwk,
  generateDPoPKeyPair,
  type DPoPKeyPair,
} from "../src/client-sdk/dpop.js";
import { blind } from "../src/crypto/toprf.js";
import { verifyJwt } from "../src/jwt/jwt.js";
import { base64UrlDecode, base64UrlEncode } from "../src/jwt/jwt.js";
import { startFakeNodes, type RunningFakeNode } from "./helpers/fake-node.js";
import { assembleAssertion } from "./helpers/sign-on-client.js";
import {
  TEST_ISSUER,
  getJson,
  postJson,
  postToken,
  startGateway,
  type RunningGateway,
} from "./helpers/gateway.js";

/**
 * Component end-to-end tests (`docs/container-split.md` sections 6 and 14).
 *
 * Three fake node servers and the gateway all listen on ephemeral ports, and every
 * assertion below travels over a real socket: the browser's sign-on and token exchange
 * are reproduced by `assembleAssertion` and the DPoP helpers, so the base64url wire of
 * section 3 and the OAuth flow of section 14 are exercised end to end.
 */

const ALICE = { username: "alice", password: "password123", sub: "usr_alice_12345" };
const TOKEN_ENDPOINT = `${TEST_ISSUER}/token`;
const REDIRECT_URI = "http://localhost:3001/callback";

let nodes: RunningFakeNode[];
let gateway: RunningGateway;
let demoDist: string;

beforeAll(async () => {
  demoDist = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-demo-dist-"));
  fs.mkdirSync(path.join(demoDist, "assets"));
  fs.writeFileSync(path.join(demoDist, "index.html"), "<!doctype html><title>demo</title>");
  fs.writeFileSync(path.join(demoDist, "assets", "app.js"), "export const ok = 1;\n");
  fs.writeFileSync(path.join(os.tmpdir(), "gateway-outside-secret.txt"), "top secret\n");

  nodes = await startFakeNodes();
  gateway = await startGateway({ nodeUrls: nodes.map((n) => n.url), demoDist });
});

afterAll(async () => {
  await gateway?.close();
  await Promise.all((nodes ?? []).map((n) => n.close()));
  fs.rmSync(demoDist, { recursive: true, force: true });
});

/** A real RFC 7638 thumbprint: SHA-256, base64url, 43 characters (section 13). */
const RP_JKT = "b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA";

interface FlowResult {
  keyPair: DPoPKeyPair;
  cnfJkt: string;
  assertion: string;
  sub: string;
}

/** Runs sign-on and assembles the assertion (the code) bound to a fresh DPoP key. */
async function signOnToCode(
  gatewayUrl: string,
  opts: { clientId?: string; scope?: string; nonce?: string; password?: string } = {}
): Promise<FlowResult> {
  const keyPair = generateDPoPKeyPair();
  const cnfJkt = calculateJwkThumbprint(exportDPoPJwk(keyPair.publicKey));
  const { assertion, sub } = await assembleAssertion({
    gatewayUrl,
    issuer: TEST_ISSUER,
    username: ALICE.username,
    password: opts.password ?? ALICE.password,
    clientId: opts.clientId ?? "demo_client",
    scope: opts.scope ?? "openid profile",
    nonce: opts.nonce ?? "c-challenge",
    cnfJkt,
  });
  return { keyPair, cnfJkt, assertion, sub };
}

describe("node discovery", () => {
  it("learns each node id from /health rather than from NODE_URLS order", async () => {
    const discovered = gateway.proxy.getNodes();
    expect(discovered.map((n) => n.nodeId)).toEqual([1, 2, 3]);
    for (const client of discovered) {
      const match = nodes.find((n) => n.url === client.url);
      expect(match?.nodeId).toBe(client.nodeId);
    }
  });

  it("refuses to start against a node from a different key ceremony", async () => {
    const impostor = http.createServer((_req, res) => {
      const body = JSON.stringify({
        status: "ok",
        nodeId: 1,
        groupPublicKey: base64UrlEncode(new Uint8Array(32)),
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    });
    await new Promise<void>((resolve) => impostor.listen(0, "127.0.0.1", () => resolve()));
    const { port } = impostor.address() as AddressInfo;

    try {
      await expect(
        startGateway({ nodeUrls: [`http://127.0.0.1:${port}`], threshold: 1 })
      ).rejects.toThrow(/different key ceremony/);
    } finally {
      impostor.closeAllConnections();
      await new Promise<void>((resolve) => impostor.close(() => resolve()));
    }
  });

  it("refuses to start when a node never comes up", async () => {
    const probe = http.createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((resolve) => probe.close(() => resolve()));

    await expect(
      startGateway({ nodeUrls: [nodes[0].url, `http://127.0.0.1:${port}`], threshold: 2 })
    ).rejects.toThrow(/Node discovery failed/);
  });
});

describe("OIDC / OAuth endpoints", () => {
  it("serves an authorization-code discovery document naming the token endpoint", async () => {
    const res = await getJson(gateway.url, "/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(TEST_ISSUER);
    expect(res.body.token_endpoint).toBe(`${TEST_ISSUER}/token`);
    expect(res.body.response_types_supported).toEqual(["code"]);
    expect(res.body.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
  });

  it("publishes the dealer's group public key as JWKS", async () => {
    const res = await getJson(gateway.url, "/jwks.json");
    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
    expect(res.body.keys[0].kid).toBe("pasta-group-key-1");
    expect(base64UrlDecode(res.body.keys[0].x)).toHaveLength(32);
  });

  it("redirects a well-formed response_type=code /authorize to the demo login", async () => {
    const query = new URLSearchParams({
      client_id: "demo_client",
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid profile",
      state: "st-1",
      dpop_jkt: RP_JKT,
    });
    const res = await getJson(gateway.url, `/authorize?${query}`);
    expect(res.status).toBe(200);
    expect(res.text).toContain("/demo?step=login");
    expect(res.text).toContain(encodeURIComponent(REDIRECT_URI));
    // A fresh challenge c is generated and carried through.
    expect(res.text).toMatch(/[?&]c=[^&"]+/);
    expect(res.text).toContain(`dpop_jkt=${RP_JKT}`);
    expect(res.text).toContain("state=st-1");
  });

  it("rejects /authorize with a non-code response_type or a missing dpop_jkt", async () => {
    const idToken = await getJson(
      gateway.url,
      `/authorize?client_id=c&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&response_type=id_token&scope=openid&dpop_jkt=${RP_JKT}`
    );
    expect(idToken.status).toBe(400);
    expect(idToken.text).toContain("code");

    const noJkt = await getJson(
      gateway.url,
      `/authorize?client_id=c&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&response_type=code&scope=openid`
    );
    expect(noJkt.status).toBe(400);
    expect(noJkt.text).toContain("dpop_jkt");
  });
});

describe("the token flow over HTTP (section 14)", () => {
  it("mints an access token and a refresh token the JWKS verifies, then refreshes", async () => {
    const jwks = await getJson(gateway.url, "/jwks.json");
    const publishedKey = base64UrlDecode(jwks.body.keys[0].x);

    const flow = await signOnToCode(gateway.url, { scope: "openid profile", nonce: "c-1" });
    const proof = createDPoPProof(flow.keyPair, "POST", TOKEN_ENDPOINT);

    const res = await postToken(
      gateway.url,
      {
        grant_type: "authorization_code",
        code: flow.assertion,
        client_id: "demo_client",
        redirect_uri: REDIRECT_URI,
      },
      proof
    );
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe("DPoP");
    expect(res.body.expires_in).toBe(3600);
    expect(res.body.scope).toBe("openid profile");

    // Access token verifies, is an at+jwt, and is bound to the RP's key.
    const at = verifyJwt(res.body.access_token, publishedKey, {
      iss: TEST_ISSUER,
      aud: "demo_client",
    });
    expect(at.valid).toBe(true);
    expect(at.header.typ).toBe("at+jwt");
    expect(at.payload.sub).toBe(ALICE.sub);
    expect(at.payload.scope).toBe("openid profile");
    expect(at.payload.cnf.jkt).toBe(flow.cnfJkt);

    // Refresh token verifies and is a refresh+jwt.
    const rt = verifyJwt(res.body.refresh_token, publishedKey, { iss: TEST_ISSUER });
    expect(rt.valid).toBe(true);
    expect(rt.header.typ).toBe("refresh+jwt");
    expect(rt.payload.sub).toBe(ALICE.sub);
    expect(rt.payload.cnf.jkt).toBe(flow.cnfJkt);

    // Refresh grant: a new proof, the node-signed refresh token, new tokens back.
    const refreshProof = createDPoPProof(flow.keyPair, "POST", TOKEN_ENDPOINT);
    const refreshed = await postToken(
      gateway.url,
      { grant_type: "refresh_token", refresh_token: res.body.refresh_token },
      refreshProof
    );
    expect(refreshed.status).toBe(200);
    const newAt = verifyJwt(refreshed.body.access_token, publishedKey, {
      iss: TEST_ISSUER,
      aud: "demo_client",
    });
    expect(newAt.valid).toBe(true);
    expect(newAt.header.typ).toBe("at+jwt");
    expect(newAt.payload.sub).toBe(ALICE.sub);
    expect(newAt.payload.cnf.jkt).toBe(flow.cnfJkt);
    const newRt = verifyJwt(refreshed.body.refresh_token, publishedKey, { iss: TEST_ISSUER });
    expect(newRt.valid).toBe(true);
    expect(newRt.header.typ).toBe("refresh+jwt");
  });

  it("puts base64url and hex on the wire and never a serialized Uint8Array", async () => {
    const { blinded } = blind(ALICE.password);
    const raw = await fetch(`${gateway.url}/api/pasta/sign-on`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: ALICE.username,
        blinded: base64UrlEncode(blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-wire",
        clientId: "demo_client",
        scope: "openid",
        nonce: "c-wire",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30,
        iss: TEST_ISSUER,
      }),
    });
    expect(raw.status).toBe(200);
    const body = await raw.json();
    for (const commitment of body.commitments) {
      expect(commitment.D).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(base64UrlDecode(commitment.D)).toHaveLength(32);
    }
    for (const nodeResponse of body.nodeResponses) {
      expect(base64UrlDecode(nodeResponse.commitment.E)).toHaveLength(32);
      expect(nodeResponse.ct_i).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  it("rejects /token with no DPoP proof", async () => {
    const flow = await signOnToCode(gateway.url);
    const res = await postToken(gateway.url, {
      grant_type: "authorization_code",
      code: flow.assertion,
      client_id: "demo_client",
      redirect_uri: REDIRECT_URI,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_dpop_proof");
  });

  it("rejects /token when the proof key is not the code's cnf.jkt", async () => {
    const flow = await signOnToCode(gateway.url);
    // A proof from a different key: right shape, wrong thumbprint.
    const otherKey = generateDPoPKeyPair();
    const proof = createDPoPProof(otherKey, "POST", TOKEN_ENDPOINT);
    const res = await postToken(
      gateway.url,
      {
        grant_type: "authorization_code",
        code: flow.assertion,
        client_id: "demo_client",
        redirect_uri: REDIRECT_URI,
      },
      proof
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_dpop_proof");
  });

  it("rejects /token for an unknown grant type and a missing code", async () => {
    const badGrant = await postToken(
      gateway.url,
      { grant_type: "password", code: "x" },
      createDPoPProof(generateDPoPKeyPair(), "POST", TOKEN_ENDPOINT)
    );
    expect(badGrant.status).toBe(400);
    expect(badGrant.body.error).toBe("unsupported_grant_type");

    const noCode = await postToken(
      gateway.url,
      { grant_type: "authorization_code", client_id: "demo_client" },
      createDPoPProof(generateDPoPKeyPair(), "POST", TOKEN_ENDPOINT)
    );
    expect(noCode.status).toBe(400);
    expect(noCode.body.error).toBe("invalid_request");
  });

  it("rejects a tampered code", async () => {
    const flow = await signOnToCode(gateway.url);
    const parts = flow.assertion.split(".");
    const tampered = `${parts[0]}.${parts[1]}.${"A".repeat(parts[2].length)}`;
    const proof = createDPoPProof(flow.keyPair, "POST", TOKEN_ENDPOINT);
    const res = await postToken(
      gateway.url,
      {
        grant_type: "authorization_code",
        code: tampered,
        client_id: "demo_client",
        redirect_uri: REDIRECT_URI,
      },
      proof
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it("still issues a token with only two of the three nodes reachable", async () => {
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      await trio[2].close();

      const jwks = await getJson(gw.url, "/jwks.json");
      const publishedKey = base64UrlDecode(jwks.body.keys[0].x);

      const flow = await signOnToCode(gw.url, { nonce: "c-2of3" });
      const proof = createDPoPProof(flow.keyPair, "POST", TOKEN_ENDPOINT);
      const res = await postToken(
        gw.url,
        {
          grant_type: "authorization_code",
          code: flow.assertion,
          client_id: "demo_client",
          redirect_uri: REDIRECT_URI,
        },
        proof
      );
      expect(res.status).toBe(200);
      const at = verifyJwt(res.body.access_token, publishedKey, {
        iss: TEST_ISSUER,
        aud: "demo_client",
      });
      expect(at.valid).toBe(true);
      expect(at.payload.cnf.jkt).toBe(flow.cnfJkt);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("answers the CORS preflight for /token with the DPoP header allowed", async () => {
    const res = await fetch(`${gateway.url}/token`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:3001");
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")).toContain("DPoP");
    expect(res.headers.get("access-control-allow-headers")).toContain("Content-Type");
  });

  it("answers the CORS preflight for /jwks.json", async () => {
    const res = await fetch(`${gateway.url}/jwks.json`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:3001");
    expect(res.headers.get("access-control-allow-methods")).toContain("GET");
    // The real GET carries the origin header too.
    const get = await fetch(`${gateway.url}/jwks.json`);
    expect(get.headers.get("access-control-allow-origin")).toBe("http://localhost:3001");
  });
});

describe("the gateway never sees a password", () => {
  it("no longer exposes the browser sign-on or refresh routes", async () => {
    const browser = await postJson(gateway.url, "/api/pasta/browser-sign-on", {
      username: ALICE.username,
      password: ALICE.password,
    });
    expect(browser.status).toBe(404);

    const refresh = await postJson(gateway.url, "/api/pasta/refresh", { sessionId: "x" });
    expect(refresh.status).toBe(404);
  });

  it("reads only username and blinded off a sign-on body, ignoring any password", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
    try {
      const withWrongPassword = await postJson(gateway.url, "/api/pasta/sign-on", {
        username: ALICE.username,
        password: "hunter2-should-be-ignored",
        blinded: base64UrlEncode(blind(ALICE.password).blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-ignores-password",
        clientId: "demo_client",
        scope: "openid",
        nonce: "c-ignores-password",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30,
        iss: TEST_ISSUER,
      });
      expect(withWrongPassword.status).toBe(200);
      expect(withWrongPassword.body.nodeResponses).toHaveLength(3);

      const printed = logs.join("\n");
      expect(printed).toContain("[gateway] sign-on   sess=");
      expect(printed).not.toContain(ALICE.password);
      expect(printed).not.toContain("hunter2");
    } finally {
      spy.mockRestore();
    }
  });

  it("fails to assemble a code on a wrong password, the gateway relaying happily", async () => {
    await expect(
      signOnToCode(gateway.url, { password: "not-the-password" })
    ).rejects.toThrow(/Invalid password or corrupted share/);
  });

  it("requires a nonce and a clientId on sign-on", async () => {
    const base = () => ({
      username: ALICE.username,
      blinded: base64UrlEncode(blind(ALICE.password).blinded.toRawBytes()),
      sessionNonce: base64UrlEncode(new Uint8Array(16)),
      cnfJkt: "jkt-required",
      clientId: "demo_client",
      scope: "openid",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 30,
      iss: TEST_ISSUER,
    });

    for (const body of [base(), { ...base(), nonce: null }, { ...base(), nonce: "" }]) {
      const res = await postJson(gateway.url, "/api/pasta/sign-on", body);
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/nonce is required/);
    }

    const noClientId = { ...base(), nonce: "c-ok" } as Record<string, unknown>;
    delete noClientId.clientId;
    const res = await postJson(gateway.url, "/api/pasta/sign-on", noClientId);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/clientId is required/);

    const ok = await postJson(gateway.url, "/api/pasta/sign-on", { ...base(), nonce: "c-ok" });
    expect(ok.status).toBe(200);
  });

  it("answers 413 rather than 500 for a body over the limit", async () => {
    const res = await fetch(`${gateway.url}/api/pasta/sign-on`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "a".repeat(1_100_000) }),
    });
    expect(res.status).toBe(413);
    expect((await res.json()).error).toMatch(/exceeds/);
  });
});

describe("demo log", () => {
  it("prints the token exchange with the access token but no password", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
    let accessToken = "";
    try {
      const flow = await signOnToCode(gateway.url, { nonce: "c-demolog" });
      const proof = createDPoPProof(flow.keyPair, "POST", TOKEN_ENDPOINT);
      const res = await postToken(
        gateway.url,
        {
          grant_type: "authorization_code",
          code: flow.assertion,
          client_id: "demo_client",
          redirect_uri: REDIRECT_URI,
        },
        proof
      );
      accessToken = res.body.access_token;
    } finally {
      spy.mockRestore();
    }

    const tokenLine = logs.find((l) => l.startsWith("[gateway] token     grant=authz"));
    expect(tokenLine).toBeDefined();
    expect(tokenLine).toContain("code(assertion)");
    expect(tokenLine).toContain(accessToken.slice(0, 16));
    expect(logs.join("\n")).not.toContain(ALICE.password);
    // The never: claim is on the startup line only.
    expect(logs.filter((l) => l.includes("never:"))).toHaveLength(0);
  });

  it("names the node it dropped when one is unreachable on sign-on", async () => {
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
    try {
      await trio.find((n) => n.nodeId === 3)!.close();
      await signOnToCode(gw.url, { nonce: "c-excluded" });

      const cont = logs.find((l) => l.includes("round1 (D,E)×2"));
      expect(cont).toBeDefined();
      expect(cont).toContain("(node3 unreachable, excluded)");
    } finally {
      spy.mockRestore();
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("logs a /token refusal as a single ✖ line", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
    try {
      const flow = await signOnToCode(gateway.url);
      await postToken(gateway.url, {
        grant_type: "authorization_code",
        code: flow.assertion,
        client_id: "demo_client",
        redirect_uri: REDIRECT_URI,
      }); // no proof
    } finally {
      spy.mockRestore();
    }
    const rejects = logs.filter((l) => l.startsWith("[gateway] ✖ token rejected:"));
    expect(rejects).toHaveLength(1);
    expect(rejects[0]).toContain("invalid_dpop_proof");
  });
});

describe("gateway /health", () => {
  it("lists every node with its id, url and reachability", async () => {
    const res = await getJson(gateway.url, "/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.nodes).toHaveLength(3);
    for (const entry of res.body.nodes) {
      expect(entry.healthy).toBe(true);
      expect([1, 2, 3]).toContain(entry.nodeId);
    }
  });

  it("answers 503 and degraded once the healthy nodes fall below the threshold", async () => {
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      await trio[1].close();
      await trio[2].close();

      const res = await getJson(gw.url, "/health");
      expect(res.status).toBe(503);
      expect(res.body.status).toBe("degraded");
      expect(res.body.nodes.filter((n: any) => n.healthy)).toHaveLength(1);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });
});

describe("node protocol over HTTP", () => {
  it("refuses to reuse a round id: a FROST nonce pair is single use", async () => {
    const node = nodes[0];
    const roundId = "round-reuse-test";

    const commit = await postJson(node.url, "/commit", { roundId });
    expect(commit.status).toBe(200);

    const body = (sessionId: string) => ({
      roundId,
      request: {
        sessionId,
        username: ALICE.username,
        blinded: base64UrlEncode(blind(ALICE.password).blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-reuse",
        clientId: "demo_client",
        scope: "openid",
        nonce: "c-reuse",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30,
        iss: TEST_ISSUER,
        commitments: [{ nodeId: commit.body.nodeId, D: commit.body.D, E: commit.body.E }],
        allParticipants: [commit.body.nodeId],
      },
    });

    const first = await postJson(node.url, "/sign-on", body("session-reuse-1"));
    expect(first.status).toBe(200);

    const second = await postJson(node.url, "/sign-on", body("session-reuse-2"));
    expect(second.status).toBe(400);
    expect(second.body.error).toMatch(/expired or not found/);
  });

  it("refuses a null nonce at the node wire boundary", async () => {
    const node = nodes[0];
    const roundId = "round-null-nonce";
    const commit = await postJson(node.url, "/commit", { roundId });
    expect(commit.status).toBe(200);

    const res = await postJson(node.url, "/sign-on", {
      roundId,
      request: {
        sessionId: "session-null-nonce",
        username: ALICE.username,
        blinded: base64UrlEncode(blind(ALICE.password).blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-null",
        clientId: "demo_client",
        scope: "openid",
        nonce: null,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30,
        iss: TEST_ISSUER,
        commitments: [{ nodeId: commit.body.nodeId, D: commit.body.D, E: commit.body.E }],
        allParticipants: [commit.body.nodeId],
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/nonce must be a string/);
  });
});

describe("static demo UI", () => {
  it("serves index.html at / and /demo, and files under /assets", async () => {
    for (const p of ["/", "/demo"]) {
      const res = await fetch(`${gateway.url}${p}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/html");
      expect(await res.text()).toContain("<title>demo</title>");
    }

    const asset = await fetch(`${gateway.url}/assets/app.js`);
    expect(asset.status).toBe(200);
    expect(asset.headers.get("content-type")).toContain("application/javascript");
    expect(await asset.text()).toContain("export const ok");
  });

  it("refuses to walk out of the dist directory", async () => {
    for (const attempt of [
      "/assets/../../gateway-outside-secret.txt",
      "/assets/..%2f..%2fgateway-outside-secret.txt",
      "/assets/%2e%2e/%2e%2e/gateway-outside-secret.txt",
    ]) {
      const res = await fetch(`${gateway.url}${attempt}`);
      const text = await res.text();
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(text).not.toContain("top secret");
    }
  });

  it("404s on an unknown path", async () => {
    const res = await fetch(`${gateway.url}/nope`);
    expect(res.status).toBe(404);
  });
});
