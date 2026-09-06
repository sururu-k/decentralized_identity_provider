import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  configFromEnv,
  DEFAULT_CLIENT_ID,
  DEFAULT_ISSUER,
  DEFAULT_PORT,
  DEFAULT_RP_BASE_URL,
  portFromEnv,
} from "../src/config.js";
import { buildAuthorizeUrl, createRpServer, redirectUriFor } from "../src/server.js";

/**
 * Component tests for the rp server, over real HTTP.
 *
 * Since the OAuth step (docs/container-split.md section 14) the server is three GET
 * routes and no state: it builds an `/authorize` URL, and it serves the callback page
 * with the code and state escaped into `data-` attributes. It never calls `/token`, never
 * fetches JWKS and never touches a key, so there is no authorization server to fake here.
 * The behaviour that used to need one now lives in the browser, and
 * `tests/token-script.test.ts` runs it under Node's WebCrypto against a fake gateway.
 */

const ISSUER = "http://idp.example.test";
const RP_BASE_URL = "http://rp.example.test";
const CLIENT_ID = "demo_client";

interface RunningRp {
  server: http.Server;
  url: string;
}

function startRp(overrides: Partial<Parameters<typeof createRpServer>[0]> = {}): Promise<RunningRp> {
  const server = createRpServer({
    rpBaseUrl: RP_BASE_URL,
    issuer: ISSUER,
    clientId: CLIENT_ID,
    ...overrides,
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` });
    });
  });
}

function stop(rp: RunningRp): Promise<void> {
  return new Promise((resolve) => rp.server.close(() => resolve()));
}

describe("rp component e2e", () => {
  let rp: RunningRp;

  beforeAll(async () => {
    rp = await startRp();
  });

  afterAll(async () => {
    await stop(rp);
  });

  it("GET /health returns ok", async () => {
    const res = await fetch(`${rp.url}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("GET / renders the landing page with an authorization-code authorize URL", async () => {
    const res = await fetch(`${rp.url}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(res.headers.get("cache-control")).toBe("no-store");
    const html = await res.text();

    const authorizeUrl = /data-authorize-url="([^"]+)"/.exec(html)?.[1] ?? "";
    expect(authorizeUrl).toContain("http://idp.example.test/authorize?");
    const params = new URL(authorizeUrl.replace(/&amp;/g, "&")).searchParams;
    expect(params.get("response_type")).toBe("code");
    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("redirect_uri")).toBe(`${RP_BASE_URL}/callback`);
    expect(params.get("scope")).toBe("openid profile email");
    expect(params.get("state")).toMatch(/^[A-Za-z0-9_-]{22}$/);
    // The implicit/OIDC parameters of the previous flow are gone.
    expect(params.get("response_mode")).toBeNull();
    expect(params.get("nonce")).toBeNull();
    // Spaces in scope are %20, not "+", matching the gateway's reference URL.
    expect(authorizeUrl).toContain("scope=openid%20profile%20email");
  });

  it("GET / ships the inline DPoP key logic and an inert login link", async () => {
    const html = await (await fetch(`${rp.url}/`)).text();
    expect(html).toContain('crypto.subtle.generateKey({ name: "Ed25519" }, false,');
    expect(html).toContain('"&dpop_jkt=" + encodeURIComponent(jkt)');
    expect(html).toContain('id="login-btn" aria-disabled="true"');
    expect(html).not.toMatch(/<a[^>]+class="login-btn"[^>]+href=/);
  });

  it("GET / generates a fresh state per request and parks it for the callback", async () => {
    const stateOf = async (): Promise<string> => {
      const html = await (await fetch(`${rp.url}/`)).text();
      return /data-state="([^"]+)"/.exec(html)?.[1] ?? "";
    };
    const first = await stateOf();
    const second = await stateOf();
    expect(first).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(first).not.toBe(second);

    const html = await (await fetch(`${rp.url}/`)).text();
    const state = /data-state="([^"]+)"/.exec(html)?.[1] ?? "";
    // The same value is in the authorize URL and in the attribute the script stores.
    expect(html).toContain(`state=${state}`);
    expect(html).toContain('sessionStorage.setItem("pasta-rp-state", state)');
  });

  it("GET /callback?code&state serves the token page with both values escaped in", async () => {
    const res = await fetch(`${rp.url}/callback?code=abc123&state=xyz789`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();

    expect(html).toContain('data-code="abc123"');
    expect(html).toContain('data-state="xyz789"');
    expect(html).toContain(`data-issuer="${ISSUER}"`);
    expect(html).toContain(`data-client-id="${CLIENT_ID}"`);
    expect(html).toContain(`data-redirect-uri="${RP_BASE_URL}/callback"`);
    // The page, not the server, spends the code.
    expect(html).toContain("PastaToken.obtainToken");
    expect(html).toContain('id="refresh-btn"');
  });

  it("passes an assertion JWT code through to the page untouched", async () => {
    // Section 14 (revised): the code is the group-signed authentication assertion, not an
    // opaque handle. It is long and contains dots; the server must not shorten or parse it.
    const assertion = [
      Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" })).toString(
        "base64url"
      ),
      Buffer.from(
        JSON.stringify({
          iss: ISSUER,
          sub: "usr_alice_12345",
          aud: ISSUER,
          cnf: { jkt: "b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA" },
          nonce: "challenge_c_value",
          iat: 1_757_000_000,
          exp: 1_757_000_060,
        })
      ).toString("base64url"),
      Buffer.alloc(64, 7).toString("base64url"),
    ].join(".");
    expect(assertion.length).toBeGreaterThan(300);

    const res = await fetch(
      `${rp.url}/callback?code=${encodeURIComponent(assertion)}&state=xyz789`
    );
    expect(res.status).toBe(200);
    const html = await res.text();

    expect(html).toContain(`data-code="${assertion}"`);
    // Nothing about the assertion is interpreted: no claim of it reaches the markup.
    expect(html).not.toContain("usr_alice_12345");
  });

  it("escapes a hostile code and state instead of letting them become markup", async () => {
    const hostile = '"><img src=x onerror=alert(1)>';
    const res = await fetch(
      `${rp.url}/callback?code=${encodeURIComponent(hostile)}&state=${encodeURIComponent(hostile)}`
    );
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;");
  });

  it("returns 400 when the redirect carries no code", async () => {
    const res = await fetch(`${rp.url}/callback`);
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("400 Bad Request");
    expect(html).toContain("認可コード");
    // No token flow on a page with no code.
    expect(html).not.toContain("PastaToken");
  });

  it("returns 400 with no code even when state is present", async () => {
    const res = await fetch(`${rp.url}/callback?state=xyz789`);
    expect(res.status).toBe(400);
  });

  it("shows the authorization server's error instead of running the token flow", async () => {
    const res = await fetch(
      `${rp.url}/callback?error=access_denied&error_description=user%20refused&state=xyz789`
    );
    expect(res.status).toBe(400);
    const html = await res.text();

    expect(html).toContain("認可に失敗しました");
    expect(html).toContain("access_denied");
    expect(html).toContain("user refused");
    expect(html).toContain("xyz789");
    expect(html).not.toContain("PastaToken");
  });

  it("prefers the error branch over a code, and escapes the error text", async () => {
    const res = await fetch(
      `${rp.url}/callback?error=${encodeURIComponent("<script>alert(1)</script>")}&code=abc`
    );
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("no longer accepts a form_post to /callback", async () => {
    // The id_token form_post of the previous flow is gone (contract section 14 廃止).
    const res = await fetch(`${rp.url}/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "id_token=x&state=y",
    });
    expect(res.status).toBe(404);
  });

  it("returns 404 for unknown routes", async () => {
    expect((await fetch(`${rp.url}/nope`)).status).toBe(404);
    expect((await fetch(`${rp.url}/jwks.json`)).status).toBe(404);
  });

  it("offers a way back to the portal from every result page", async () => {
    const pages = await Promise.all(
      [
        `${rp.url}/callback?code=abc&state=xyz`,
        `${rp.url}/callback`,
        `${rp.url}/callback?error=access_denied`,
      ].map(async (url) => (await fetch(url)).text())
    );
    for (const html of pages) {
      expect(html).toContain('href="/"');
    }
  });
});

describe("URL construction", () => {
  const config = { rpBaseUrl: RP_BASE_URL, issuer: ISSUER, clientId: CLIENT_ID };

  it("uses one redirect_uri at /authorize and at /token", () => {
    // The value is compared byte for byte by the authorization server, so it has to come
    // from the same place both times.
    expect(redirectUriFor(config)).toBe(`${RP_BASE_URL}/callback`);
    expect(buildAuthorizeUrl(config, "st")).toContain(
      `redirect_uri=${encodeURIComponent(`${RP_BASE_URL}/callback`)}`
    );
  });

  it("keeps openid in scope, which the gateway's /authorize still expects", () => {
    expect(buildAuthorizeUrl(config, "st")).toContain("scope=openid%20profile%20email");
  });

  it("never produces a double slash from a trailing slash in configuration", () => {
    const trimmed = configFromEnv({
      ISSUER: "http://idp.example.test/",
      RP_BASE_URL: "http://rp.example.test///",
    });
    expect(buildAuthorizeUrl(trimmed, "st")).toContain("http://idp.example.test/authorize?");
    expect(redirectUriFor(trimmed)).toBe("http://rp.example.test/callback");
  });
});

describe("demo log", () => {
  let rp: RunningRp;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(async () => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1";
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    rp = await startRp();
  });

  afterEach(async () => {
    await stop(rp);
    logSpy.mockRestore();
    process.env = { ...ORIGINAL_ENV };
  });

  function rpLines(): string[] {
    return logSpy.mock.calls.map((call) => call[0] as string).filter((l) => l.startsWith("[rp]"));
  }

  it("GET / logs one landing line carrying the state it just issued", async () => {
    const html = await (await fetch(`${rp.url}/`)).text();
    const state = /data-state="([^"]+)"/.exec(html)?.[1] ?? "";

    const lines = rpLines();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe(`[rp]      landing   state=${state}  → authorize URL`);
    // No nonce any more: this is OAuth, not OIDC.
    expect(lines[0]).not.toContain("nonce");
  });

  it("GET /callback logs the code truncated to 8 chars and says the browser takes over", async () => {
    await fetch(`${rp.url}/callback?code=code_abcdefghijklmnop&state=st-1`);

    const lines = rpLines();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe(
      "[rp]      callback  state=st-1  ← code(assertion) code_abc " +
        "(query, via browser redirect)  → page with token script"
    );
    // The log names what the code actually is: a signed assertion, not a database key.
    expect(lines[0]).toContain("code(assertion)");
    // The server never saw a token, so it cannot log one.
    expect(lines[0]).not.toContain("access_token");
  });

  it("a callback with no code logs one ✖ line and nothing else", async () => {
    await fetch(`${rp.url}/callback`);
    const lines = rpLines();
    expect(lines).toEqual(["[rp]      ✖ callback rejected: no code in the redirect query string"]);
  });

  it("an error redirect logs the authorization server's error code", async () => {
    await fetch(`${rp.url}/callback?error=access_denied&error_description=nope`);
    const lines = rpLines();
    expect(lines).toEqual([
      "[rp]      ✖ callback rejected: authorization server returned error=access_denied (nope)",
    ]);
  });

  it("DEMO_LOG=0 suppresses [rp] output entirely", async () => {
    process.env.DEMO_LOG = "0";
    await fetch(`${rp.url}/`);
    await fetch(`${rp.url}/callback?code=abc&state=st`);
    await fetch(`${rp.url}/callback`);
    expect(rpLines()).toHaveLength(0);
  });
});

describe("portFromEnv", () => {
  it("falls back to 3001 for unset, blank and nonsense values", () => {
    expect(portFromEnv({})).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "   " })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "abc" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "3.5" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "-1" })).toBe(DEFAULT_PORT);
    expect(portFromEnv({ PORT: "70000" })).toBe(DEFAULT_PORT);
  });

  it("honours a valid port, including 0 for an ephemeral bind", () => {
    expect(portFromEnv({ PORT: "8080" })).toBe(8080);
    expect(portFromEnv({ PORT: "0" })).toBe(0);
  });
});

describe("configFromEnv", () => {
  it("applies the contract's defaults", () => {
    expect(configFromEnv({})).toEqual({
      rpBaseUrl: DEFAULT_RP_BASE_URL,
      issuer: DEFAULT_ISSUER,
      clientId: DEFAULT_CLIENT_ID,
    });
  });

  it("trims trailing slashes from both base URLs", () => {
    expect(
      configFromEnv({ ISSUER: "http://gw:3000//", RP_BASE_URL: "http://rp:3001/" })
    ).toEqual({
      rpBaseUrl: "http://rp:3001",
      issuer: "http://gw:3000",
      clientId: DEFAULT_CLIENT_ID,
    });
  });

  it("has no JWKS host setting: the browser fetches /jwks.json from ISSUER", () => {
    // IDP_INTERNAL_URL was removed with the server-side verifier. An environment that
    // still sets it must be ignored rather than silently pointing the browser at a
    // compose-internal hostname it cannot resolve.
    const config = configFromEnv({
      ISSUER: "http://localhost:3000",
      IDP_INTERNAL_URL: "http://gateway:3000",
    } as Record<string, string>);
    expect(config).toEqual({
      rpBaseUrl: DEFAULT_RP_BASE_URL,
      issuer: "http://localhost:3000",
      clientId: DEFAULT_CLIENT_ID,
    });
    expect(Object.keys(config)).not.toContain("idpInternalUrl");
  });
});
