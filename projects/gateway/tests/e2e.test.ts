import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { DecentralizedClientSdk } from "../src/client-sdk/client.js";
import { createDPoPProof } from "../src/client-sdk/dpop.js";
import { blind } from "../src/crypto/toprf.js";
import { CONTINUATION_INDENT } from "../src/demolog.js";
import { verifyJwt } from "../src/jwt/jwt.js";
import { base64UrlDecode, base64UrlEncode } from "../src/jwt/jwt.js";
import { startFakeNodes, type RunningFakeNode } from "./helpers/fake-node.js";
import {
  TEST_ISSUER,
  getJson,
  postForm,
  postJson,
  startGateway,
  type RunningGateway,
} from "./helpers/gateway.js";

/**
 * Component end-to-end tests (`docs/container-split.md` section 6).
 *
 * Three fake node servers and the gateway all listen on ephemeral ports, and every
 * assertion below travels over a real socket: the client SDK runs in its HTTP
 * (`proxyUrl`) mode, so the base64url wire contract of section 3 is exercised in both
 * directions rather than bypassed by in-process calls.
 */

const ALICE = { username: "alice", password: "password123", sub: "usr_alice_12345" };

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

describe("node discovery", () => {
  it("learns each node id from /health rather than from NODE_URLS order", async () => {
    // The fake nodes bind ports in whatever order the OS hands them out, so the URL list
    // is not sorted by node id. Discovery must still pair every URL with the right id.
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
        // 32 zero bytes: a valid base64url point, but not this group's key.
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
    // Bind and immediately release a port, so nothing is listening there.
    const probe = http.createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((resolve) => probe.close(() => resolve()));

    await expect(
      startGateway({ nodeUrls: [nodes[0].url, `http://127.0.0.1:${port}`], threshold: 2 })
    ).rejects.toThrow(/Node discovery failed/);
  });
});

describe("OIDC endpoints", () => {
  it("serves a discovery document naming the configured issuer", async () => {
    const res = await getJson(gateway.url, "/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(TEST_ISSUER);
    expect(res.body.jwks_uri).toBe(`${TEST_ISSUER}/jwks.json`);
    expect(res.body.response_modes_supported).toContain("form_post");
  });

  it("publishes the dealer's group public key as JWKS", async () => {
    const res = await getJson(gateway.url, "/jwks.json");
    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
    expect(res.body.keys[0].kid).toBe("pasta-group-key-1");
    expect(base64UrlDecode(res.body.keys[0].x)).toHaveLength(32);
  });

  it("redirects a well-formed /authorize to the demo login step", async () => {
    const query = new URLSearchParams({
      client_id: "demo_client",
      redirect_uri: "http://rp.example/callback",
      response_type: "id_token",
      response_mode: "form_post",
      scope: "openid profile",
      nonce: "n-authorize",
      state: "st-1",
      dpop_jkt: RP_JKT,
    });
    const res = await getJson(gateway.url, `/authorize?${query}`);
    expect(res.status).toBe(200);
    expect(res.text).toContain("/demo?step=login");
    expect(res.text).toContain(encodeURIComponent("http://rp.example/callback"));
    expect(res.text).toContain("nonce=n-authorize");
    // Section 13: the RP front end's thumbprint reaches the demo UI untouched.
    expect(res.text).toContain(`dpop_jkt=${RP_JKT}`);
  });

  it("rejects /authorize without a nonce, and with a non form_post response_mode", async () => {
    const noNonce = await getJson(
      gateway.url,
      "/authorize?client_id=c&redirect_uri=http://rp.example/cb&response_type=id_token&scope=openid"
    );
    expect(noNonce.status).toBe(400);
    expect(noNonce.text).toContain("nonce");

    const badMode = await getJson(
      gateway.url,
      "/authorize?client_id=c&redirect_uri=http://rp.example/cb&response_type=id_token" +
        "&response_mode=query&scope=openid&nonce=n"
    );
    expect(badMode.status).toBe(400);
    expect(badMode.text).toContain("form_post");

    const badType = await getJson(
      gateway.url,
      "/authorize?client_id=c&redirect_uri=http://rp.example/cb&response_type=code&scope=openid&nonce=n"
    );
    expect(badType.status).toBe(400);
  });

  it("rejects /authorize when dpop_jkt is missing or malformed", async () => {
    const base =
      "/authorize?client_id=c&redirect_uri=http://rp.example/cb&response_type=id_token" +
      "&response_mode=form_post&scope=openid&nonce=n";

    const missing = await getJson(gateway.url, base);
    expect(missing.status).toBe(400);
    expect(missing.text).toContain("Authorize Error:");
    expect(missing.text).toContain("dpop_jkt");

    const tooLong = await getJson(gateway.url, `${base}&dpop_jkt=${RP_JKT}A`);
    expect(tooLong.status).toBe(400);
    expect(tooLong.text).toContain("dpop_jkt");

    const padded = await getJson(
      gateway.url,
      `${base}&dpop_jkt=${encodeURIComponent(RP_JKT.slice(0, 42) + "=")}`
    );
    expect(padded.status).toBe(400);
    expect(padded.text).toContain("dpop_jkt");
  });
});

describe("sign-on and refresh over HTTP", () => {
  it("mints an id_token the published JWKS verifies, then refreshes it", async () => {
    const jwks = await getJson(gateway.url, "/jwks.json");
    const publishedKey = base64UrlDecode(jwks.body.keys[0].x);

    const sdk = new DecentralizedClientSdk({ proxyUrl: gateway.url, issuer: TEST_ISSUER });

    const nonce = "n-signon-1";
    const { id_token, sessionId } = await sdk.signOn({
      username: ALICE.username,
      password: ALICE.password,
      clientId: "demo_client",
      nonce,
    });

    expect(typeof sessionId).toBe("string");

    const verified = verifyJwt(id_token, publishedKey, {
      iss: TEST_ISSUER,
      aud: "demo_client",
      nonce,
    });
    expect(verified.valid).toBe(true);
    expect(verified.payload.sub).toBe(ALICE.sub);
    expect(verified.payload.cnf.jkt).toBe(sdk.cnfJkt);

    const refreshUrl = `${gateway.url}/api/pasta/refresh`;
    const refreshed = await sdk.refresh({
      clientId: "demo_client",
      nonce: "n-refresh-1",
      refreshEndpointUrl: refreshUrl,
    });

    const refreshedVerify = verifyJwt(refreshed.id_token, publishedKey, {
      iss: TEST_ISSUER,
      aud: "demo_client",
      nonce: "n-refresh-1",
    });
    expect(refreshedVerify.valid).toBe(true);
    expect(refreshedVerify.payload.sub).toBe(ALICE.sub);
  });

  it("puts base64url on the wire, never a serialized Uint8Array", async () => {
    const res = await postJson(gateway.url, "/api/pasta/sign-on", {
      username: ALICE.username,
      // A syntactically valid but wrong blinded point still exercises the wire shape of
      // the reply, so decode it from a real sign-on instead: run one through the SDK.
      blinded: "invalid",
      sessionNonce: "AAAAAAAAAAAAAAAAAAAAAA",
      cnfJkt: "jkt",
      nonce: "n-wire-invalid",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      aud: "demo_client",
      iss: TEST_ISSUER,
    });
    // A malformed blinded point is a caller error, not a gateway fault.
    expect(res.status).toBe(400);
    expect(typeof res.body.error).toBe("string");

    // Now the shape of a successful reply, driven by a genuine blinded point.
    const { blinded } = blind(ALICE.password);
    const raw = await fetch(`${gateway.url}/api/pasta/sign-on`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: ALICE.username,
        blinded: base64UrlEncode(blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-wire",
        nonce: "n-wire",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
      }),
    });
    expect(raw.status).toBe(200);
    const body = await raw.json();
    for (const commitment of body.commitments) {
      expect(typeof commitment.D).toBe("string");
      expect(commitment.D).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(base64UrlDecode(commitment.D)).toHaveLength(32);
    }
    for (const nodeResponse of body.nodeResponses) {
      expect(typeof nodeResponse.commitment.D).toBe("string");
      expect(base64UrlDecode(nodeResponse.commitment.E)).toHaveLength(32);
    }
  });

  it("still signs on with only two of the three nodes configured", async () => {
    const twoNodes = await startGateway({
      nodeUrls: [nodes[0].url, nodes[1].url],
      demoDist,
    });
    try {
      const sdk = new DecentralizedClientSdk({ proxyUrl: twoNodes.url, issuer: TEST_ISSUER });
      const { id_token } = await sdk.signOn({
        username: ALICE.username,
        password: ALICE.password,
        clientId: "demo_client",
        nonce: "n-2of3",
      });
      const jwks = await getJson(twoNodes.url, "/jwks.json");
      const verified = verifyJwt(id_token, base64UrlDecode(jwks.body.keys[0].x), {
        iss: TEST_ISSUER,
      });
      expect(verified.valid).toBe(true);

      const refreshed = await sdk.refresh({
        clientId: "demo_client",
        nonce: "n-2of3-refresh",
        refreshEndpointUrl: `${twoNodes.url}/api/pasta/refresh`,
      });
      expect(
        verifyJwt(refreshed.id_token, base64UrlDecode(jwks.body.keys[0].x), { iss: TEST_ISSUER })
          .valid
      ).toBe(true);
    } finally {
      await twoNodes.close();
    }
  });

  it("forms a quorum from the nodes that answer when one is down", async () => {
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      await trio[2].close();

      const sdk = new DecentralizedClientSdk({ proxyUrl: gw.url, issuer: TEST_ISSUER });
      const { id_token } = await sdk.signOn({
        username: ALICE.username,
        password: ALICE.password,
        clientId: "demo_client",
        nonce: "n-degraded",
      });
      const jwks = await getJson(gw.url, "/jwks.json");
      expect(
        verifyJwt(id_token, base64UrlDecode(jwks.body.keys[0].x), { iss: TEST_ISSUER }).valid
      ).toBe(true);

      // With only one node left the threshold can no longer be met.
      await trio[1].close();
      const failing = new DecentralizedClientSdk({ proxyUrl: gw.url, issuer: TEST_ISSUER });
      await expect(
        failing.signOn({
          username: ALICE.username,
          password: ALICE.password,
          clientId: "demo_client",
          nonce: "n-below-threshold",
        })
      ).rejects.toThrow(/status 400/);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("refreshes over the reachable half of the sign-on quorum after a node dies", async () => {
    // The path the contract calls out in section 6: a session is established by all
    // three nodes, one of them then goes away, and a refresh that names no participants
    // has to re-form a quorum out of the survivors. Only the nodes that signed hold an
    // `rs_i` for this session, so the gateway must go back to the recorded set and drop
    // the unreachable member rather than falling back to its whole roster.
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      const sdk = new DecentralizedClientSdk({ proxyUrl: gw.url, issuer: TEST_ISSUER });
      const { sessionId } = await sdk.signOn({
        username: ALICE.username,
        password: ALICE.password,
        clientId: "demo_client",
        nonce: "n-refresh-after-outage",
      });

      // All three signed, so all three are on the session record.
      expect(gw.proxy.getSessionManager().getSessionParticipants(sessionId)).toEqual([1, 2, 3]);

      const downNode = trio.find((n) => n.nodeId === 3)!;
      await downNode.close();

      const refreshUrl = `${gw.url}/api/pasta/refresh`;
      const refreshed = await sdk.refresh({
        clientId: "demo_client",
        nonce: "n-refresh-after-outage-2",
        refreshEndpointUrl: refreshUrl,
        // participants deliberately unset: the gateway chooses.
      });

      const jwks = await getJson(gw.url, "/jwks.json");
      const verified = verifyJwt(refreshed.id_token, base64UrlDecode(jwks.body.keys[0].x), {
        iss: TEST_ISSUER,
        aud: "demo_client",
        nonce: "n-refresh-after-outage-2",
      });
      expect(verified.valid).toBe(true);
      expect(verified.payload.sub).toBe(ALICE.sub);
      expect(verified.payload.cnf.jkt).toBe(sdk.cnfJkt);

      // And the quorum really was the two survivors, not the full roster: a raw refresh
      // shows which nodes answered round 2.
      const raw = await postJson(gw.url, "/api/pasta/refresh", {
        sessionId,
        dpopProof: createDPoPProof(sdk.getDPoPKeyPair(), "POST", refreshUrl),
        expectedHtu: refreshUrl,
        nonce: "n-refresh-raw",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
      });
      expect(raw.status).toBe(200);
      expect(raw.body.nodeResponses.map((r: any) => r.nodeId).sort()).toEqual([1, 2]);
      expect(raw.body.commitments.map((c: any) => c.nodeId).sort()).toEqual([1, 2]);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("routes an unqualified refresh to the sign-on quorum, not to the whole roster", async () => {
    // The discriminating case for section 6's rule that a refresh goes back to the nodes
    // that signed on. Alice signs on with nodes 1 and 2 only, while node 3 stays up and
    // reachable. A gateway that refreshed against its full roster would pull in node 3,
    // which holds no `rs_i` for this session and rejects the request, and round 2 is all
    // or nothing -- so the refresh only succeeds if the recorded set is what is used.
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      const sdk = new DecentralizedClientSdk({ proxyUrl: gw.url, issuer: TEST_ISSUER });
      const { sessionId } = await sdk.signOn({
        username: ALICE.username,
        password: ALICE.password,
        clientId: "demo_client",
        nonce: "n-partial-quorum",
        participants: [1, 2],
      });

      expect(gw.proxy.getSessionManager().getSessionParticipants(sessionId)).toEqual([1, 2]);
      // Node 3 is healthy and would be picked up by a roster-wide refresh.
      const health = await getJson(gw.url, "/health");
      expect(health.body.nodes.filter((n: any) => n.healthy)).toHaveLength(3);

      const refreshUrl = `${gw.url}/api/pasta/refresh`;
      const refreshed = await sdk.refresh({
        clientId: "demo_client",
        nonce: "n-partial-quorum-2",
        refreshEndpointUrl: refreshUrl,
      });
      const jwks = await getJson(gw.url, "/jwks.json");
      expect(
        verifyJwt(refreshed.id_token, base64UrlDecode(jwks.body.keys[0].x), {
          iss: TEST_ISSUER,
          aud: "demo_client",
          nonce: "n-partial-quorum-2",
        }).valid
      ).toBe(true);

      const raw = await postJson(gw.url, "/api/pasta/refresh", {
        sessionId,
        dpopProof: createDPoPProof(sdk.getDPoPKeyPair(), "POST", refreshUrl),
        expectedHtu: refreshUrl,
        nonce: "n-refresh-raw",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
      });
      expect(raw.status).toBe(200);
      expect(raw.body.nodeResponses.map((r: any) => r.nodeId).sort()).toEqual([1, 2]);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("fails a refresh once the sign-on quorum drops below the threshold", async () => {
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      const sdk = new DecentralizedClientSdk({ proxyUrl: gw.url, issuer: TEST_ISSUER });
      await sdk.signOn({
        username: ALICE.username,
        password: ALICE.password,
        clientId: "demo_client",
        nonce: "n-refresh-below",
      });

      await trio[1].close();
      await trio[2].close();

      await expect(
        sdk.refresh({
          clientId: "demo_client",
          nonce: "n-refresh-below-2",
          refreshEndpointUrl: `${gw.url}/api/pasta/refresh`,
        })
      ).rejects.toThrow(/status 400/);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("refuses an explicit participant list when one of those nodes is down", async () => {
    // An explicit list is a request for a specific quorum. Substituting a different one
    // would be a surprise, so the gateway fails instead (section 6, proxy layer rules).
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      await trio[2].close();
      const { blinded } = blind(ALICE.password);
      const res = await postJson(gw.url, "/api/pasta/sign-on", {
        username: ALICE.username,
        blinded: base64UrlEncode(blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-explicit",
        nonce: "n-explicit",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
        participants: [1, 2, 3],
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/did not all commit/);

      // The same request naming only the survivors succeeds.
      const ok = await postJson(gw.url, "/api/pasta/sign-on", {
        username: ALICE.username,
        blinded: base64UrlEncode(blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-explicit",
        nonce: "n-explicit",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
        participants: [1, 2],
      });
      expect(ok.status).toBe(200);
      expect(ok.body.nodeResponses.map((r: any) => r.nodeId).sort()).toEqual([1, 2]);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("requires a nonce on sign-on, whatever shape the caller left it in", async () => {
    // `nonce` is mandatory at the gateway door (`docs/container-split.md` section 6).
    // The reference `deterministicJsonStringify` writes an absent one out as
    // `"nonce":undefined`, so a sign-on without it mints a token whose payload is not
    // valid JSON -- correctly signed, and unparseable by every relying party. A literal
    // `null` is refused for the same reason, before it can burn a FROST round.
    const base = () => ({
      username: ALICE.username,
      blinded: base64UrlEncode(blind(ALICE.password).blinded.toRawBytes()),
      sessionNonce: base64UrlEncode(new Uint8Array(16)),
      cnfJkt: "jkt-nonce-required",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      aud: "demo_client",
      iss: TEST_ISSUER,
    });

    for (const body of [base(), { ...base(), nonce: null }, { ...base(), nonce: "" }]) {
      const res = await postJson(gateway.url, "/api/pasta/sign-on", body);
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/nonce is required/);
    }

    // The identical request with a nonce goes through, so the 400 is about the nonce
    // and nothing else in the body.
    const ok = await postJson(gateway.url, "/api/pasta/sign-on", {
      ...base(),
      nonce: "n-nonce-required",
    });
    expect(ok.status).toBe(200);
  });

  it("requires a nonce on refresh, checked before the session lookup", async () => {
    const sdk = new DecentralizedClientSdk({ proxyUrl: gateway.url, issuer: TEST_ISSUER });
    const { sessionId } = await sdk.signOn({
      username: ALICE.username,
      password: ALICE.password,
      clientId: "demo_client",
      nonce: "n-refresh-nonce-required",
    });
    const refreshUrl = `${gateway.url}/api/pasta/refresh`;

    for (const nonce of [undefined, null, ""]) {
      const body: Record<string, unknown> = {
        sessionId,
        dpopProof: createDPoPProof(sdk.getDPoPKeyPair(), "POST", refreshUrl),
        expectedHtu: refreshUrl,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
      };
      if (nonce !== undefined) body.nonce = nonce;

      const res = await postJson(gateway.url, "/api/pasta/refresh", body);
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/nonce is required/);
    }
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

  it("refuses a refresh for an unknown session", async () => {
    const res = await postJson(gateway.url, "/api/pasta/refresh", {
      sessionId: "00000000-0000-4000-8000-000000000000",
      dpopProof: "not.a.proof",
      expectedHtu: `${gateway.url}/api/pasta/refresh`,
      nonce: "n-unknown-session",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      aud: "demo_client",
      iss: TEST_ISSUER,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("invalid or revoked");
  });
});

describe("the gateway never sees a password", () => {
  it("no longer exposes the browser sign-on route at all", async () => {
    // Section 11: the client SDK moved into the browser, so the one route that ever
    // accepted a plaintext password is gone rather than merely unused.
    const res = await postJson(gateway.url, "/api/pasta/browser-sign-on", {
      username: ALICE.username,
      password: ALICE.password,
      clientId: "demo_client",
      nonce: "n-browser-gone",
    });
    expect(res.status).toBe(404);
  });

  it("reads only username and blinded off a sign-on body, ignoring any password", async () => {
    // Two discriminating requests. The first carries a password that is wrong for alice
    // and a blinded point that is right; it succeeds, so the password was not consulted.
    // The second carries alice's real password and an unknown username; it fails, so the
    // username -- not the password -- is what selects the record.
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
        nonce: "n-ignores-password",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
      });
      expect(withWrongPassword.status).toBe(200);
      expect(withWrongPassword.body.nodeResponses).toHaveLength(3);

      const withRightPasswordUnknownUser = await postJson(gateway.url, "/api/pasta/sign-on", {
        username: "mallory",
        password: ALICE.password,
        blinded: base64UrlEncode(blind(ALICE.password).blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(new Uint8Array(16)),
        cnfJkt: "jkt-unknown-user",
        nonce: "n-unknown-user",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
      });
      expect(withRightPasswordUnknownUser.status).toBe(400);

      // Nothing the gateway printed carries either password, not even truncated.
      const printed = logs.join("\n");
      expect(printed).toContain("[gateway] sign-on   sess=");
      expect(printed).not.toContain(ALICE.password);
      expect(printed).not.toContain("hunter2");
    } finally {
      spy.mockRestore();
    }
  });

  it("fails inside the SDK on a wrong password, with the gateway relaying happily", async () => {
    // The wrong-password path is now entirely client side: every node answers, the
    // gateway returns 200, and the AEAD open fails in the browser because `h` is wrong.
    // The gateway cannot tell this attempt apart from a successful one.
    const sdk = new DecentralizedClientSdk({ proxyUrl: gateway.url, issuer: TEST_ISSUER });
    await expect(
      sdk.signOn({
        username: ALICE.username,
        password: "not-the-password",
        clientId: "demo_client",
        nonce: "n-wrong-password",
      })
    ).rejects.toThrow(/Invalid password or corrupted share/);
  });

  it("mints a token whose claims a relying party can actually parse", async () => {
    // The regression the nonce rule exists for: the signature verifying is not enough,
    // the payload has to be JSON. Decoded here without the gateway's own helpers, the
    // way an RP would.
    const sdk = new DecentralizedClientSdk({ proxyUrl: gateway.url, issuer: TEST_ISSUER });
    const { id_token } = await sdk.signOn({
      username: ALICE.username,
      password: ALICE.password,
      clientId: "demo_client",
      nonce: "n-parseable",
    });

    const [headerB64, payloadB64] = id_token.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
    expect(header.alg).toBe("EdDSA");
    // The `rp` component selects its verification key by `kid`, so this has to be the
    // `keyId` the gateway publishes in its JWKS.
    const jwks = await getJson(gateway.url, "/jwks.json");
    expect(header.kid).toBe(jwks.body.keys[0].kid);
    expect(payload.nonce).toBe("n-parseable");
    expect(payload.aud).toBe("demo_client");
  });
});

describe("demo log", () => {
  it("prints one sign-on event as one line plus one continuation", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });

    let idToken: string;
    try {
      const sdk = new DecentralizedClientSdk({ proxyUrl: gateway.url, issuer: TEST_ISSUER });
      ({ id_token: idToken } = await sdk.signOn({
        username: ALICE.username,
        password: ALICE.password,
        clientId: "demo_client",
        nonce: "n-demolog",
      }));
    } finally {
      spy.mockRestore();
    }

    const headingIndex = logs.findIndex((l) => l.startsWith("[gateway] sign-on   "));
    expect(headingIndex).toBeGreaterThanOrEqual(0);
    const [head, cont] = logs.slice(headingIndex, headingIndex + 2);

    expect(head).toMatch(/^\[gateway\] sign-on   sess=\S+ round=\S+ user=alice nonce=n-demolog {2}← A /);
    expect(head).toContain("(no pw)");
    expect(cont.startsWith(CONTINUATION_INDENT)).toBe(true);
    expect(cont).toContain("round1 (D,E)×3 → round2");
    expect(cont).toContain("ct_i×3 (no h_i, cannot decrypt)");
    expect(cont).not.toContain("excluded");
    // The `never:` claim is made once, on the startup line, never on an event.
    expect(logs.filter((l) => l.includes("never:"))).toHaveLength(0);

    // No colour: the test gateway builds its logger with a non-TTY sink, so the lines a
    // structural assertion runs over are the same bytes an audience reads.
    expect(logs.join("\n")).not.toContain("\u001b[");
    expect(logs.join("\n")).not.toContain(ALICE.password);
    expect(typeof idToken).toBe("string");
  });

  it("names the node it dropped when one is unreachable", async () => {
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
    try {
      await trio.find((n) => n.nodeId === 3)!.close();

      const sdk = new DecentralizedClientSdk({ proxyUrl: gw.url, issuer: TEST_ISSUER });
      await sdk.signOn({
        username: ALICE.username,
        password: ALICE.password,
        clientId: "demo_client",
        nonce: "n-demolog-excluded",
      });

      const head = logs.find((l) => l.startsWith("[gateway] sign-on   "));
      expect(head).toContain("user=alice");
      const cont = logs.find((l) => l.startsWith(`${CONTINUATION_INDENT}round1 `));
      expect(cont).toContain("(node3 unreachable, excluded)");
      expect(cont).toContain("round1 (D,E)×2");
    } finally {
      spy.mockRestore();
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });

  it("logs a refusal as a single ✖ line", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
    try {
      const res = await postJson(gateway.url, "/api/pasta/refresh", {
        sessionId: "00000000-0000-4000-8000-000000000000",
        dpopProof: "not.a.proof",
        expectedHtu: `${gateway.url}/api/pasta/refresh`,
        nonce: "n-reject-log",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
        iss: TEST_ISSUER,
      });
      expect(res.status).toBe(400);
    } finally {
      spy.mockRestore();
    }

    const rejects = logs.filter((l) => l.startsWith("[gateway] ✖ refresh rejected:"));
    expect(rejects).toHaveLength(1);
    expect(rejects[0]).toContain("invalid or revoked");
  });

  it("prints a one-line event for the public OIDC endpoints", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
    try {
      await getJson(gateway.url, "/jwks.json");
      await getJson(gateway.url, "/.well-known/openid-configuration");
      await getJson(
        gateway.url,
        "/authorize?client_id=demo_client&redirect_uri=http%3A%2F%2Frp.example%2Fcb" +
          "&response_type=id_token&response_mode=form_post&scope=openid&nonce=n-authorize-log" +
          `&state=st&dpop_jkt=${RP_JKT}`
      );
    } finally {
      spy.mockRestore();
    }

    expect(logs).toContain("[gateway] jwks      public only");
    expect(logs).toContain("[gateway] discovery public only");
    expect(logs).toContain(
      "[gateway] authorize client_id=demo_client nonce=n-authorize-log state=st " +
        `dpop_jkt=${RP_JKT.slice(0, 8)}  → redirect /demo`
    );
  });
});

describe("demo RP callback", () => {
  it("shows a verified payload for a real token and a failure for a tampered one", async () => {
    const sdk = new DecentralizedClientSdk({ proxyUrl: gateway.url, issuer: TEST_ISSUER });
    const { id_token: idToken } = await sdk.signOn({
      username: ALICE.username,
      password: ALICE.password,
      clientId: "demo_client",
      nonce: "n-rp-callback",
    });

    const ok = await postForm(gateway.url, "/demo/rp-callback", {
      id_token: idToken,
      state: "state-abc",
    });
    expect(ok.status).toBe(200);
    expect(ok.text).toContain("検証成功");
    expect(ok.text).toContain(ALICE.sub);
    expect(ok.text).toContain("state-abc");

    const parts = idToken.split(".");
    const tampered = `${parts[0]}.${parts[1]}.${"A".repeat(parts[2].length)}`;
    const bad = await postForm(gateway.url, "/demo/rp-callback", { id_token: tampered });
    expect(bad.status).toBe(200);
    expect(bad.text).toContain("検証失敗");

    const missing = await postForm(gateway.url, "/demo/rp-callback", { state: "x" });
    expect(missing.status).toBe(400);
  });

  it("escapes the state parameter instead of reflecting it as markup", async () => {
    // `state` is an unauthenticated form field echoed onto a page served from the
    // gateway's own origin, next to the demo UI. Reflecting it raw is script running as
    // the IdP.
    const payload = '</pre><script>alert(document.domain)</script><pre>';
    const res = await postForm(gateway.url, "/demo/rp-callback", {
      id_token: "not.a.token",
      state: payload,
    });
    expect(res.status).toBe(200);
    expect(res.text).not.toContain("<script>alert(document.domain)</script>");
    expect(res.text).toContain("&lt;script&gt;");
  });

  it("escapes a verification error built from an unsigned JWT header", async () => {
    // No valid signature is needed to reach this: `verifyJwt` reports an unsupported
    // `alg` before it checks anything, and `alg` comes straight out of the header the
    // caller wrote.
    const header = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify({ alg: "<img src=x onerror=alert(1)>" }))
    );
    const res = await postForm(gateway.url, "/demo/rp-callback", {
      id_token: `${header}.e30.AAAA`,
      state: "s",
    });
    expect(res.status).toBe(200);
    expect(res.text).toContain("検証失敗");
    expect(res.text).not.toContain("<img src=x onerror=alert(1)>");
    expect(res.text).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("escapes claims echoed from a genuinely verified token", async () => {
    const sdk = new DecentralizedClientSdk({ proxyUrl: gateway.url, issuer: TEST_ISSUER });
    const { id_token } = await sdk.signOn({
      username: ALICE.username,
      password: ALICE.password,
      clientId: "<b>aud</b>",
      nonce: "<i>nonce</i>",
    });

    const res = await postForm(gateway.url, "/demo/rp-callback", {
      id_token,
      state: "s",
    });
    expect(res.status).toBe(200);
    expect(res.text).toContain("検証成功");
    expect(res.text).not.toContain("<b>aud</b>");
    expect(res.text).toContain("&lt;b&gt;aud&lt;/b&gt;");
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
      expect(typeof entry.url).toBe("string");
      expect([1, 2, 3]).toContain(entry.nodeId);
    }
  });

  it("reports a node that has gone away as unhealthy", async () => {
    const trio = await startFakeNodes();
    const gw = await startGateway({ nodeUrls: trio.map((n) => n.url), demoDist });
    try {
      await trio[1].close();
      const res = await getJson(gw.url, "/health");
      // Two of three still answer, so the gateway itself is usable.
      expect(res.status).toBe(200);
      const down = res.body.nodes.find((n: any) => n.nodeId === trio[1].nodeId);
      expect(down.healthy).toBe(false);
      expect(res.body.nodes.filter((n: any) => n.healthy)).toHaveLength(2);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
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
      expect(res.body.nodes).toHaveLength(3);
      expect(res.body.nodes.filter((n: any) => n.healthy)).toHaveLength(1);
    } finally {
      await gw.close();
      await Promise.all(trio.map((n) => n.close()));
    }
  });
});

describe("node protocol over HTTP", () => {
  it("refuses to reuse a round id: a FROST nonce pair is single use", async () => {
    // The gateway draws a fresh `roundId` per request, so this is only reachable against
    // a node directly. It is the property the gateway depends on when it treats round 2
    // as all or nothing.
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
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
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
        nonce: null,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        aud: "demo_client",
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
