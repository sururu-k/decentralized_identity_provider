import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { configFromEnv, DEFAULT_PORT, portFromEnv } from "../src/config.js";
import { createRpServer } from "../src/server.js";

/**
 * Component e2e tests. Everything below goes over real HTTP: a fake JWKS server
 * stands in for the gateway, and the RP is started on port 0 pointed at it.
 *
 * The signing key is generated here with node:crypto — the tests share no code
 * with the IdP, which is the point of the RP being a standalone verifier.
 */

const ISSUER = "http://idp.example.test";
const CLIENT_ID = "demo_client";
const KID = "pasta-group-key-1";

// ---------------------------------------------------------------------------
// Test-local JWT signing helpers (independent of the RP implementation)
// ---------------------------------------------------------------------------

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const otherKeyPair = crypto.generateKeyPairSync("ed25519");

/** base64url without padding — the same shape as the IdP's `base64UrlEncode`. */
function b64u(input: Buffer | string): string {
  return (typeof input === "string" ? Buffer.from(input, "utf8") : input).toString("base64url");
}

function jwkFor(key: crypto.KeyObject, kid: string) {
  const jwk = key.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, kid, use: "sig", alg: "EdDSA" };
}

interface SignOptions {
  kid?: string;
  key?: crypto.KeyObject;
  header?: Record<string, unknown>;
}

function signJwt(payload: Record<string, unknown>, options: SignOptions = {}): string {
  const header = { alg: "EdDSA", typ: "JWT", kid: options.kid ?? KID, ...options.header };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, "ascii"), options.key ?? privateKey);
  return `${signingInput}.${b64u(signature)}`;
}

function validPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    sub: "usr_alice_12345",
    aud: CLIENT_ID,
    iat: now,
    exp: now + 3600,
    nonce: "test_nonce_value",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Fake JWKS server (stands in for the gateway)
// ---------------------------------------------------------------------------

interface FakeJwks {
  server: http.Server;
  url: string;
  /** How many times /jwks.json has been fetched. */
  hits: number;
  /** Set to a status code to make the endpoint fail. */
  failWith: number | null;
  keys: object[];
}

function startFakeJwks(): Promise<FakeJwks> {
  const state: FakeJwks = {
    server: undefined as unknown as http.Server,
    url: "",
    hits: 0,
    failWith: null,
    keys: [jwkFor(publicKey, KID)],
  };
  state.server = http.createServer((req, res) => {
    if (req.url !== "/jwks.json") {
      res.writeHead(404).end();
      return;
    }
    state.hits += 1;
    if (state.failWith !== null) {
      res.writeHead(state.failWith, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unavailable" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ keys: state.keys }));
  });
  return new Promise((resolve) => {
    state.server.listen(0, "127.0.0.1", () => {
      const { port } = state.server.address() as AddressInfo;
      state.url = `http://127.0.0.1:${port}`;
      resolve(state);
    });
  });
}

function startRp(idpInternalUrl: string): Promise<{ server: http.Server; url: string }> {
  const server = createRpServer({
    rpBaseUrl: "http://rp.example.test:3001",
    issuer: ISSUER,
    idpInternalUrl,
    clientId: CLIENT_ID,
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

/**
 * Runs one test against a fresh fake-JWKS + RP pair, tearing both down even when
 * the body throws, so a failing assertion cannot leak a listening socket.
 */
async function withFreshRp(
  fn: (ctx: { rp: { server: http.Server; url: string }; jwks: FakeJwks }) => Promise<void>
): Promise<void> {
  const jwks = await startFakeJwks();
  const rp = await startRp(jwks.url);
  try {
    await fn({ rp, jwks });
  } finally {
    await closeServer(rp.server);
    await closeServer(jwks.server);
  }
}

async function postCallback(rpUrl: string, form: Record<string, string>) {
  const response = await fetch(`${rpUrl}/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  return { status: response.status, html: await response.text() };
}

// ---------------------------------------------------------------------------

describe("rp component e2e", () => {
  let jwks: FakeJwks;
  let rp: { server: http.Server; url: string };

  beforeAll(async () => {
    jwks = await startFakeJwks();
    rp = await startRp(jwks.url);
  });

  afterAll(async () => {
    await closeServer(rp.server);
    await closeServer(jwks.server);
  });

  it("GET /health returns ok", async () => {
    const response = await fetch(`${rp.url}/health`);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: "ok" });
  });

  it("GET / renders the landing page with a form_post authorize URL", async () => {
    const response = await fetch(`${rp.url}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    const html = await response.text();

    expect(html).toContain("ZK-App Portal");
    expect(html).toContain("PASTA IdP でログイン");
    // redirect_uri points back at this RP's /callback, percent-encoded.
    expect(html).toContain("redirect_uri=http%3A%2F%2Frp.example.test%3A3001%2Fcallback");
    expect(html).toContain("response_mode=form_post");
    expect(html).toContain("response_type=id_token");
    expect(html).toContain("scope=openid%20profile%20email");
    expect(html).toContain(`client_id=${CLIENT_ID}`);
    expect(html).toContain(`${ISSUER}/authorize?`);
  });

  it("GET / generates a fresh nonce and state per request", async () => {
    const extract = (html: string, key: string) =>
      new RegExp(`${key}=([A-Za-z0-9_-]+)`).exec(html)?.[1];
    const first = await (await fetch(`${rp.url}/`)).text();
    const second = await (await fetch(`${rp.url}/`)).text();

    expect(extract(first, "nonce")).toBeTruthy();
    expect(extract(first, "state")).toBeTruthy();
    expect(extract(first, "nonce")).not.toBe(extract(second, "nonce"));
    expect(extract(first, "state")).not.toBe(extract(second, "state"));
  });

  it("accepts a valid id_token and shows the success page with the sub", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload()),
      state: "rp-demo-state",
    });

    expect(status).toBe(200);
    expect(html).toContain("認証成功");
    expect(html).toContain("usr_alice_12345");
    expect(html).toContain("Ed25519 (EdDSA) — 有効");
    // state is displayed, never enforced.
    expect(html).toContain("rp-demo-state");
    expect(html).not.toContain("認証失敗");
  });

  it("rejects a tampered payload", async () => {
    const token = signJwt(validPayload());
    const [header, , signature] = token.split(".");
    const forged = b64u(JSON.stringify(validPayload({ sub: "usr_attacker" })));
    const { status, html } = await postCallback(rp.url, {
      id_token: `${header}.${forged}.${signature}`,
    });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");
    expect(html).toContain("signature verification failed");
    expect(html).not.toContain("認証成功");
  });

  it("rejects a token signed by a different key", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload(), { key: otherKeyPair.privateKey }),
    });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");
    expect(html).toContain("signature verification failed");
  });

  it("rejects an iss mismatch", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload({ iss: "http://evil.example.test" })),
    });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");
    expect(html).toContain("iss mismatch");
  });

  it("rejects an aud mismatch", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload({ aud: "someone_else" })),
    });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");
    expect(html).toContain("aud mismatch");
  });

  it("accepts an aud array that contains the client_id", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload({ aud: ["other_client", CLIENT_ID] })),
    });

    expect(status).toBe(200);
    expect(html).toContain("認証成功");
  });

  it("rejects an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload({ iat: now - 7200, exp: now - 3600 })),
    });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");
    expect(html).toContain("expired");
  });

  it("rejects a token issued far in the future beyond the 60s skew", async () => {
    const now = Math.floor(Date.now() / 1000);
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload({ iat: now + 600, exp: now + 4200 })),
    });

    expect(status).toBe(401);
    expect(html).toContain("issued in the future");
  });

  it("rejects a non-EdDSA alg header", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload(), { header: { alg: "none" } }),
    });

    expect(status).toBe(401);
    expect(html).toContain("unsupported alg");
  });

  it("rejects a malformed token", async () => {
    const { status, html } = await postCallback(rp.url, { id_token: "not-a-jwt" });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");
    expect(html).toContain("Malformed JWT");
  });

  it("returns 400 when id_token is missing", async () => {
    const { status, html } = await postCallback(rp.url, { state: "rp-demo" });

    expect(status).toBe(400);
    expect(html).toContain("400");
    expect(html).toContain("Missing id_token");
  });

  it("refetches the JWKS once for an unknown kid, then fails", async () => {
    const before = jwks.hits;
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload(), { kid: "unknown-kid" }),
    });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");
    expect(html).toContain("unknown-kid");
    // Exactly one extra fetch: the cache miss triggers a single refresh.
    expect(jwks.hits).toBe(before + 1);
  });

  it("picks up a rotated key on the refetch", async () => {
    const rotated = crypto.generateKeyPairSync("ed25519");
    jwks.keys = [jwkFor(publicKey, KID), jwkFor(rotated.publicKey, "rotated-kid")];

    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload(), { kid: "rotated-kid", key: rotated.privateKey }),
    });

    expect(status).toBe(200);
    expect(html).toContain("認証成功");
  });

  it("caches the JWKS across callbacks with a known kid", async () => {
    // Warm the cache, then confirm a second known-kid callback issues no fetch.
    await postCallback(rp.url, { id_token: signJwt(validPayload()) });
    const before = jwks.hits;
    const { status } = await postCallback(rp.url, { id_token: signJwt(validPayload()) });

    expect(status).toBe(200);
    expect(jwks.hits).toBe(before);
  });

  it("returns 404 for unknown routes", async () => {
    const response = await fetch(`${rp.url}/nope`);
    expect(response.status).toBe(404);
  });

  it("escapes token content so a hostile sub cannot inject markup", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload({ sub: "<script>alert(1)</script>" })),
    });

    expect(status).toBe(200);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("rp with an unreachable JWKS endpoint", () => {
  let rp: { server: http.Server; url: string };

  beforeAll(async () => {
    // Port 1 on loopback: nothing listens there, so the fetch fails outright.
    rp = await startRp("http://127.0.0.1:1");
  });

  afterAll(async () => {
    await closeServer(rp.server);
  });

  it("returns 502 when the JWKS cannot be fetched", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload()),
    });

    expect(status).toBe(502);
    expect(html).toContain("502");
    expect(html).toContain("JWKS");
  });
});

describe("rp when the JWKS endpoint errors", () => {
  let jwks: FakeJwks;
  let rp: { server: http.Server; url: string };

  beforeAll(async () => {
    jwks = await startFakeJwks();
    jwks.failWith = 500;
    rp = await startRp(jwks.url);
  });

  afterAll(async () => {
    await closeServer(rp.server);
    await closeServer(jwks.server);
  });

  it("returns 502 on a JWKS HTTP error", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload()),
    });

    expect(status).toBe(502);
    expect(html).toContain("502");
  });

  it("recovers once the JWKS endpoint comes back", async () => {
    jwks.failWith = null;
    const { status, html } = await postCallback(rp.url, {
      id_token: signJwt(validPayload()),
    });

    expect(status).toBe(200);
    expect(html).toContain("認証成功");
  });
});

// ---------------------------------------------------------------------------
// Interop with the real IdP wire format.
//
// The RP must accept exactly what the gateway/SDK emits. The gateway is not
// imported here (the RP project shares no code with it), so the token and the
// JWKS document are rebuilt byte for byte from the reference implementation's
// rules: `deterministicJsonStringify` sorts object keys before encoding, the
// header is {alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1"}, the payload
// carries iss/sub/aud/iat/exp/nonce/cnf.jkt, and the JWKS entry is
// {kty, crv, x, kid, use, alg} with x = base64url(raw 32-byte public key).
// ---------------------------------------------------------------------------

/** Byte-for-byte copy of the IdP's `deterministicJsonStringify` ordering rule. */
function deterministicJsonStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(deterministicJsonStringify).join(",") + "]";
  }
  const record = obj as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + deterministicJsonStringify(record[k])).join(",") +
    "}"
  );
}

/** The raw 32 Ed25519 public key bytes, as the gateway holds `groupPublicKey`. */
function rawPublicKeyBytes(key: crypto.KeyObject): Buffer {
  const der = key.export({ type: "spki", format: "der" });
  return Buffer.from(der.subarray(der.length - 32));
}

describe("interop with the gateway's JWT and JWKS wire format", () => {
  const idpKeys = crypto.generateKeyPairSync("ed25519");
  const groupPublicKey = rawPublicKeyBytes(idpKeys.publicKey);

  // Exactly `OidcEndpointHandler.getJwks()`.
  const gatewayJwks = {
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        x: groupPublicKey.toString("base64url"),
        kid: KID,
        use: "sig",
        alg: "EdDSA",
      },
    ],
  };

  // Exactly `createSigningInput(header, payload)` + `assembleJwt`.
  function issueGatewayStyleToken(overrides: Record<string, unknown> = {}): string {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: "EdDSA", typ: "JWT", kid: KID };
    const payload = {
      iss: ISSUER,
      sub: "usr_alice_12345",
      aud: CLIENT_ID,
      iat: now,
      exp: now + 3600,
      nonce: "random_nonce",
      cnf: { jkt: "0d1s7hDZ0aY2pV3q4rS5tU6vW7xX8yY9zZ-AbCdEfGh" },
      ...overrides,
    };
    const headerB64 = b64u(deterministicJsonStringify(header));
    const payloadB64 = b64u(deterministicJsonStringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign(
      null,
      new TextEncoder().encode(signingInput),
      idpKeys.privateKey
    );
    return `${headerB64}.${payloadB64}.${b64u(signature)}`;
  }

  let jwksServer: http.Server;
  let rp: { server: http.Server; url: string };

  beforeAll(async () => {
    jwksServer = http.createServer((req, res) => {
      if (req.url !== "/jwks.json") {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(gatewayJwks));
    });
    await new Promise<void>((resolve) =>
      jwksServer.listen(0, "127.0.0.1", () => resolve())
    );
    const { port } = jwksServer.address() as AddressInfo;
    rp = await startRp(`http://127.0.0.1:${port}`);
  });

  afterAll(async () => {
    await closeServer(rp.server);
    await closeServer(jwksServer);
  });

  it("sanity: the rebuilt header matches the reference byte string", () => {
    expect(deterministicJsonStringify({ alg: "EdDSA", typ: "JWT", kid: KID })).toBe(
      '{"alg":"EdDSA","kid":"pasta-group-key-1","typ":"JWT"}'
    );
  });

  it("accepts a token in the gateway's exact serialisation", async () => {
    const { status, html } = await postCallback(rp.url, {
      id_token: issueGatewayStyleToken(),
      state: "rp-demo",
    });

    expect(status).toBe(200);
    expect(html).toContain("認証成功");
    expect(html).toContain("usr_alice_12345");
    // The cnf/jkt confirmation claim survives into the displayed claim set.
    expect(html).toContain("jkt");
  });

  it("rejects a gateway-shaped token whose sub was swapped after signing", async () => {
    const token = issueGatewayStyleToken();
    const [header, payload, signature] = token.split(".");
    const tamperedPayload = b64u(
      deterministicJsonStringify({
        ...JSON.parse(Buffer.from(payload, "base64url").toString("utf8")),
        sub: "usr_attacker",
      })
    );
    const { status, html } = await postCallback(rp.url, {
      id_token: `${header}.${tamperedPayload}.${signature}`,
    });

    expect(status).toBe(401);
    expect(html).toContain("signature verification failed");
    expect(html).not.toContain("認証成功");
  });
});

// ---------------------------------------------------------------------------

describe("rp hardening", () => {
  it("fetches the JWKS only once when the very first callback has an unknown kid", async () => {
    let hits = 0;
    const jwksServer = http.createServer((_req, res) => {
      hits += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ keys: [jwkFor(publicKey, KID)] }));
    });
    await new Promise<void>((resolve) => jwksServer.listen(0, "127.0.0.1", () => resolve()));
    const { port } = jwksServer.address() as AddressInfo;
    const rp = await startRp(`http://127.0.0.1:${port}`);

    // Cold cache: there is no stale document to refresh, so one fetch is enough.
    const { status } = await postCallback(rp.url, {
      id_token: signJwt(validPayload(), { kid: "never-issued" }),
    });

    expect(status).toBe(401);
    expect(hits).toBe(1);

    await closeServer(rp.server);
    await closeServer(jwksServer);
  });

  it("answers 401, not 500, when the JWKS holds junk entries", async () => {
    const jwksServer = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ keys: [null, "not-a-key", [], { kty: "RSA", n: "x" }] }));
    });
    await new Promise<void>((resolve) => jwksServer.listen(0, "127.0.0.1", () => resolve()));
    const { port } = jwksServer.address() as AddressInfo;
    const rp = await startRp(`http://127.0.0.1:${port}`);

    const { status, html } = await postCallback(rp.url, { id_token: signJwt(validPayload()) });

    expect(status).toBe(401);
    expect(html).toContain("認証失敗");

    await closeServer(rp.server);
    await closeServer(jwksServer);
  });

  it("answers 413 instead of dropping the connection on an oversized body", async () => {
    const rp = await startRp("http://127.0.0.1:1");

    const response = await fetch(`${rp.url}/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `id_token=${"A".repeat(2_000_000)}`,
    });
    const html = await response.text();

    expect(response.status).toBe(413);
    expect(html).toContain("413");

    await closeServer(rp.server);
  });

  it("rejects a token whose exp is not a number", async () => {
    await withFreshRp(async ({ rp }) => {
      const { status, html } = await postCallback(rp.url, {
        id_token: signJwt(validPayload({ exp: "9999999999" })),
      });

      expect(status).toBe(401);
      expect(html).toContain("exp claim");
    });
  });

  it("escapes a hostile state value from the form_post body", async () => {
    await withFreshRp(async ({ rp }) => {
      const { status, html } = await postCallback(rp.url, {
        id_token: signJwt(validPayload()),
        state: '"><img src=x onerror=alert(1)>',
      });

      expect(status).toBe(200);
      expect(html).not.toContain("<img src=x");
      expect(html).toContain("&lt;img src=x");
    });
  });

  it("keeps the cached JWKS when a bogus kid forces a refetch that fails", async () => {
    await withFreshRp(async ({ rp, jwks }) => {
      // Warm the cache while the IdP is up.
      const warm = await postCallback(rp.url, { id_token: signJwt(validPayload()) });
      expect(warm.status).toBe(200);

      // IdP goes down, then an unknown kid asks for a refetch that cannot succeed.
      jwks.failWith = 503;
      const unknownKid = await postCallback(rp.url, {
        id_token: signJwt(validPayload(), { kid: "bogus-kid" }),
      });
      expect(unknownKid.status).toBe(502);

      // The good document must survive: a known kid still verifies offline.
      const { status, html } = await postCallback(rp.url, { id_token: signJwt(validPayload()) });
      expect(status).toBe(200);
      expect(html).toContain("認証成功");
    });
  });

  it("accepts an iss that differs from the configured issuer only by a trailing slash", async () => {
    await withFreshRp(async ({ rp }) => {
      const { status, html } = await postCallback(rp.url, {
        id_token: signJwt(validPayload({ iss: `${ISSUER}/` })),
      });

      expect(status).toBe(200);
      expect(html).toContain("認証成功");
    });
  });

  it("omits the state row when the form_post carries an empty state", async () => {
    await withFreshRp(async ({ rp }) => {
      const { status, html } = await postCallback(rp.url, {
        id_token: signJwt(validPayload({ nonce: undefined })),
        state: "",
      });

      expect(status).toBe(200);
      expect(html).not.toContain("表示のみ");
    });
  });

  it("offers a way back to the portal from every result page", async () => {
    await withFreshRp(async ({ rp, jwks }) => {
      const success = await postCallback(rp.url, { id_token: signJwt(validPayload()) });
      const failure = await postCallback(rp.url, { id_token: "not-a-jwt" });
      const missing = await postCallback(rp.url, { state: "x" });
      jwks.failWith = 503;
      const badGateway = await postCallback(rp.url, {
        id_token: signJwt(validPayload(), { kid: "another-unknown-kid" }),
      });

      expect(badGateway.status).toBe(502);
      for (const { html } of [success, failure, missing, badGateway]) {
        expect(html).toContain('href="/"');
      }
      // Only the callback page offers the IdP demo link.
      expect(success.html).toContain(`href="${ISSUER}/demo"`);
    });
  });
});

// ---------------------------------------------------------------------------
// Demo log (docs/container-split.md section 10): compact 1-2 line events, prefixed [rp].
// ---------------------------------------------------------------------------

describe("demo log", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("GET / logs a landing event with its own nonce/state", async () => {
    await withFreshRp(async ({ rp }) => {
      logSpy.mockClear();
      await fetch(`${rp.url}/`);

      const lines = logSpy.mock.calls.map((call) => String(call[0]));
      const landing = lines.find((l) => l.includes("landing   "));
      expect(landing).toBeDefined();
      expect(landing).toMatch(/^\[rp\] {6}landing {3}nonce=\S+ state=\S+ {2}→ authorize URL$/);
      // The claim about what the rp never holds belongs to the startup line only.
      expect(lines.some((l) => l.includes("never:"))).toBe(false);
    });
  });

  it("a successful /callback logs one arrival line plus the verification line, no ✖", async () => {
    await withFreshRp(async ({ rp }) => {
      logSpy.mockClear();
      const { status } = await postCallback(rp.url, {
        id_token: signJwt(validPayload()),
        state: "rp-demo-state",
      });
      expect(status).toBe(200);

      const lines = logSpy.mock.calls.map((call) => String(call[0]));
      const callbackLines = lines.filter((l) => l.includes("callback") || l.includes("JWKS kid="));
      expect(
        callbackLines.some(
          (l) =>
            l.includes("[rp]      callback  state=rp-demo-state") &&
            l.includes("← id_token") &&
            l.includes("direct from browser, not via gateway")
        )
      ).toBe(true);
      expect(
        callbackLines.some((l) => l.includes("JWKS kid=") && l.includes("Ed25519 ✓"))
      ).toBe(true);
      expect(callbackLines.some((l) => l.includes("sub=usr_alice_12345"))).toBe(true);
      expect(callbackLines.some((l) => l.includes("✖"))).toBe(false);
    });
  });

  it("a failed /callback logs the arrival line plus one ✖ line and no verification line", async () => {
    await withFreshRp(async ({ rp }) => {
      const token = signJwt(validPayload());
      const [header, , signature] = token.split(".");
      const forged = Buffer.from(
        JSON.stringify(validPayload({ sub: "usr_attacker" })),
        "utf8"
      ).toString("base64url");

      logSpy.mockClear();
      const { status } = await postCallback(rp.url, { id_token: `${header}.${forged}.${signature}` });
      expect(status).toBe(401);

      const lines = logSpy.mock.calls.map((call) => String(call[0]));
      const callbackLines = lines.filter((l) => l.includes("[rp]") || l.includes("JWKS kid="));
      expect(callbackLines.some((l) => l.includes("callback  ") && l.includes("← id_token"))).toBe(
        true
      );
      expect(callbackLines.some((l) => l.includes("Ed25519 ✓"))).toBe(false);
      const failureLines = callbackLines.filter((l) => l.includes("✖"));
      expect(failureLines).toHaveLength(1);
      // The refusal sits in the tag column, like every other event's first line.
      expect(failureLines[0].startsWith("[rp]      ✖ callback rejected:")).toBe(true);
      expect(failureLines[0]).toContain("signature verification failed");
    });
  });

  it("DEMO_LOG=0 suppresses [rp] output entirely", async () => {
    const previous = process.env.DEMO_LOG;
    process.env.DEMO_LOG = "0";
    try {
      await withFreshRp(async ({ rp }) => {
        logSpy.mockClear();
        await fetch(`${rp.url}/`);
        await postCallback(rp.url, { id_token: signJwt(validPayload()) });

        const rpLines = logSpy.mock.calls
          .map((call) => String(call[0]))
          .filter((l) => l.startsWith("[rp]"));
        expect(rpLines).toHaveLength(0);
      });
    } finally {
      if (previous === undefined) delete process.env.DEMO_LOG;
      else process.env.DEMO_LOG = previous;
    }
  });
});

describe("portFromEnv", () => {
  it("falls back to 3001 for unset, blank and nonsense values", () => {
    expect(portFromEnv({})).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "   " })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "http" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "3001.5" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "70000" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "-1" })).toBe(DEFAULT_PORT);
  });

  it("honours a valid port, including 0 for an ephemeral bind", () => {
    expect(portFromEnv({ PORT: "3001" })).toBe(3001);
    expect(portFromEnv({ PORT: " 8080 " })).toBe(8080);
    expect(portFromEnv({ PORT: "0" })).toBe(0);
  });
});

describe("configFromEnv", () => {
  it("applies the contract's defaults", () => {
    expect(configFromEnv({})).toEqual({
      rpBaseUrl: "http://localhost:3001",
      issuer: "http://localhost:3000",
      idpInternalUrl: "http://localhost:3000",
      clientId: "demo_client",
    });
  });

  it("falls back to ISSUER when IDP_INTERNAL_URL is unset, and trims slashes", () => {
    expect(configFromEnv({ ISSUER: "http://idp.test/", RP_BASE_URL: "http://rp.test//" })).toEqual({
      rpBaseUrl: "http://rp.test",
      issuer: "http://idp.test",
      idpInternalUrl: "http://idp.test",
      clientId: "demo_client",
    });
  });

  it("uses IDP_INTERNAL_URL for JWKS while iss stays the browser-visible issuer", () => {
    const config = configFromEnv({
      ISSUER: "http://localhost:3000",
      IDP_INTERNAL_URL: "http://gateway:3000",
    });
    expect(config.issuer).toBe("http://localhost:3000");
    expect(config.idpInternalUrl).toBe("http://gateway:3000");
  });
});
