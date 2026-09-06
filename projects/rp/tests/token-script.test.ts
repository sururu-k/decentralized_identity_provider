import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TOKEN_SCRIPT } from "../src/html.js";

/**
 * Tests for the inline `/token` client that ships inside the callback page.
 *
 * The rp front end is where the whole OAuth token step happens (docs/container-split.md
 * section 14): DPoP proof, `POST /token`, JWKS fetch, Ed25519 verification. None of that
 * is TypeScript — it is a string embedded in an HTML page, with no build step and no
 * runtime dependency — so nothing else would ever compile or execute it.
 *
 * There is no browser in this environment, so these tests stand in for one. `TOKEN_SCRIPT`
 * is evaluated with `new Function` and run under Node's WebCrypto, which implements the
 * same `crypto.subtle` surface a browser does (Ed25519 included since Node 20). The
 * counterparties are built with `node:crypto`, which shares no code with the script:
 *
 *  - a proof made by the script is verified with `crypto.verify`;
 *  - an access token signed with `crypto.sign` is accepted by the script, and every
 *    tampered variant of it is rejected;
 *  - a fake gateway on port 0 serves `/token` and `/jwks.json`, and the script's whole
 *    flow function runs against it over real HTTP.
 *
 * What this cannot cover: IndexedDB (no Node implementation), so the key-store half of
 * the flow — `PastaDpop.ensureKeyMaterial` — is supplied here as a plain object, and its
 * IndexedDB path is checked by reading. `projects/rp/README.md` records that gap.
 */

const ISSUER_CLIENT_ID = "demo_client";
const KID = "pasta-group-key-1";

interface PublicJwk {
  kty: string;
  crv: string;
  x: string;
}

interface KeyMaterial {
  privateKey: CryptoKey;
  publicJwk: PublicJwk;
  jkt: string;
}

interface VerifyCheck {
  label: string;
  ok: boolean;
  detail: string;
}

interface VerifyResult {
  valid: boolean;
  error: string;
  checks: VerifyCheck[];
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
}

interface PastaTokenApi {
  bytesToBase64Url: (bytes: Uint8Array) => string;
  textToBase64Url: (text: string) => string;
  base64UrlToBytes: (value: string) => Uint8Array;
  base64UrlToText: (value: string) => string;
  randomId: () => string;
  createProof: (
    material: KeyMaterial,
    params: { htm: string; htu: string; iat?: number; jti?: string }
  ) => Promise<string>;
  decodeJwt: (token: string) => {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signingInput: string;
    signature: Uint8Array;
  };
  selectJwk: (jwks: unknown, kid: unknown) => PublicJwk | null;
  verifyAccessToken: (
    accessToken: string,
    jwks: unknown,
    expected: { issuer: string; clientId: string; jkt: string; now?: number }
  ) => Promise<VerifyResult>;
  requestToken: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  obtainToken: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
}

/** Evaluates the inline script and hands back its `PastaToken` namespace. */
function loadPastaToken(): PastaTokenApi {
  return new Function(`${TOKEN_SCRIPT}\nreturn PastaToken;`)() as PastaTokenApi;
}

/** base64url without padding, computed independently of the code under test. */
function b64u(input: Buffer | string): string {
  return (typeof input === "string" ? Buffer.from(input, "utf8") : input).toString("base64url");
}

/** RFC 7638 thumbprint, computed with node:crypto rather than the script. */
function referenceJkt(jwk: PublicJwk): string {
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(
    jwk.kty
  )},"x":${JSON.stringify(jwk.x)}}`;
  return crypto.createHash("sha256").update(canonical, "utf8").digest("base64url");
}

/** A WebCrypto key pair packaged the way `PastaDpop.ensureKeyMaterial` packages one. */
async function makeKeyMaterial(): Promise<KeyMaterial> {
  const pair = (await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const exported = (await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  const publicJwk: PublicJwk = {
    crv: String(exported.crv),
    kty: String(exported.kty),
    x: String(exported.x),
  };
  return { privateKey: pair.privateKey, publicJwk, jkt: referenceJkt(publicJwk) };
}

// ---------------------------------------------------------------------------
// The "authorization server" side: node:crypto only, no shared code
// ---------------------------------------------------------------------------

const signingKeyPair = crypto.generateKeyPairSync("ed25519");
const otherKeyPair = crypto.generateKeyPairSync("ed25519");

function jwksFor(key: crypto.KeyObject, kid: string): { keys: object[] } {
  const jwk = key.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  return { keys: [{ kty: jwk.kty, crv: jwk.crv, x: jwk.x, kid, use: "sig", alg: "EdDSA" }] };
}

const JWKS = jwksFor(signingKeyPair.publicKey, KID);

interface TokenOverrides {
  header?: Record<string, unknown>;
  key?: crypto.KeyObject;
}

/** Mints an access token in the shape section 14 step 11 describes. */
function signAccessToken(
  payload: Record<string, unknown>,
  overrides: TokenOverrides = {}
): string {
  const header = { alg: "EdDSA", typ: "at+jwt", kid: KID, ...overrides.header };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const signature = crypto.sign(
    null,
    Buffer.from(signingInput, "ascii"),
    overrides.key ?? signingKeyPair.privateKey
  );
  return `${signingInput}.${b64u(signature)}`;
}

/**
 * The authorization code, which since the section 14 revision is the authentication
 * assertion itself: the group-signed JWT the IdP front end assembled. Signed here with
 * the same node:crypto key the JWKS advertises, because the fake gateway only has to see
 * a JWT-shaped code — verifying it is the real gateway's and the nodes' job.
 */
function signAssertion(overrides: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "EdDSA", typ: "JWT", kid: KID };
  const payload = {
    iss: "http://idp.test",
    sub: "usr_alice_12345",
    aud: "http://idp.test",
    cnf: { jkt: "placeholder" },
    nonce: "challenge_c_value",
    iat: now,
    exp: now + 60,
    ...overrides,
  };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const signature = crypto.sign(
    null,
    Buffer.from(signingInput, "ascii"),
    signingKeyPair.privateKey
  );
  return `${signingInput}.${b64u(signature)}`;
}

function accessTokenPayload(
  issuer: string,
  jkt: string,
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: issuer,
    sub: "usr_alice_12345",
    aud: ISSUER_CLIENT_ID,
    scope: "openid profile email",
    cnf: { jkt },
    iat: now,
    exp: now + 3600,
    jti: "tok_1",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

describe("the inline token script: encoding helpers", () => {
  const PastaToken = loadPastaToken();

  it("base64url-encodes bytes without padding, matching node:crypto", () => {
    for (let length = 0; length < 40; length++) {
      const bytes = crypto.randomBytes(length);
      expect(PastaToken.bytesToBase64Url(new Uint8Array(bytes))).toBe(bytes.toString("base64url"));
    }
  });

  it("round-trips UTF-8 text through base64url, multi-byte characters included", () => {
    for (const text of ["", "a", "hello", '{"iss":"http://x"}', "日本語テキスト", "🔐"]) {
      const encoded = PastaToken.textToBase64Url(text);
      expect(encoded).toBe(b64u(text));
      expect(encoded).not.toContain("=");
      expect(PastaToken.base64UrlToText(encoded)).toBe(text);
    }
  });

  it("decodes base64url that a signature would produce, for every remainder length", () => {
    for (let length = 1; length < 40; length++) {
      const bytes = crypto.randomBytes(length);
      const decoded = PastaToken.base64UrlToBytes(bytes.toString("base64url"));
      expect(Buffer.from(decoded)).toEqual(bytes);
    }
  });

  it("makes 128-bit random ids that never repeat across a batch", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const id = PastaToken.randomId();
      expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
      ids.add(id);
    }
    expect(ids.size).toBe(200);
  });
});

describe("the inline token script: DPoP proof", () => {
  const PastaToken = loadPastaToken();

  it("produces a proof node:crypto can verify with the embedded public key", async () => {
    const material = await makeKeyMaterial();
    const iat = 1_757_000_000;
    const proof = await PastaToken.createProof(material, {
      htm: "POST",
      htu: "http://idp.test/token",
      iat,
      jti: "jti-fixed",
    });

    const [headerPart, payloadPart, signaturePart] = proof.split(".");
    const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));

    // RFC 9449 section 4.2.
    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("EdDSA");
    expect(header.jwk).toEqual({
      kty: material.publicJwk.kty,
      crv: material.publicJwk.crv,
      x: material.publicJwk.x,
    });
    // The public key travels; nothing private does. Ed25519 private material would show
    // up as the JWK "d" member, and the key is non-extractable anyway.
    expect(Object.keys(header.jwk).sort()).toEqual(["crv", "kty", "x"]);
    expect(Buffer.from(headerPart, "base64url").toString("utf8")).not.toContain('"d"');
    expect(payload).toEqual({
      jti: "jti-fixed",
      htm: "POST",
      htu: "http://idp.test/token",
      iat,
    });

    // Verified with node:crypto, from the JWK in the header the receiver would use.
    const publicKey = crypto.createPublicKey({ key: header.jwk, format: "jwk" });
    const ok = crypto.verify(
      null,
      Buffer.from(`${headerPart}.${payloadPart}`, "ascii"),
      publicKey,
      Buffer.from(signaturePart, "base64url")
    );
    expect(ok).toBe(true);

    // The thumbprint of the header JWK is the jkt the session is bound to.
    expect(referenceJkt(header.jwk)).toBe(material.jkt);
  });

  it("defaults jti and iat, and never reuses a jti", async () => {
    const material = await makeKeyMaterial();
    const before = Math.floor(Date.now() / 1000);
    const jtis = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const proof = await PastaToken.createProof(material, {
        htm: "POST",
        htu: "http://idp.test/token",
      });
      const payload = JSON.parse(Buffer.from(proof.split(".")[1], "base64url").toString("utf8"));
      expect(payload.iat).toBeGreaterThanOrEqual(before);
      expect(payload.iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 1);
      jtis.add(payload.jti);
    }
    expect(jtis.size).toBe(5);
  });

  it("fails verification if a single byte of the proof is changed", async () => {
    const material = await makeKeyMaterial();
    const proof = await PastaToken.createProof(material, {
      htm: "POST",
      htu: "http://idp.test/token",
    });
    const [headerPart, payloadPart, signaturePart] = proof.split(".");
    const tampered = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    tampered.htm = "GET";
    const publicKey = crypto.createPublicKey({
      key: JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8")).jwk,
      format: "jwk",
    });

    const ok = crypto.verify(
      null,
      Buffer.from(`${headerPart}.${b64u(JSON.stringify(tampered))}`, "ascii"),
      publicKey,
      Buffer.from(signaturePart, "base64url")
    );
    expect(ok).toBe(false);
  });
});

describe("the inline token script: JWT decomposition", () => {
  const PastaToken = loadPastaToken();

  it("splits a token into header, payload and raw signature bytes", () => {
    const token = signAccessToken(accessTokenPayload("http://idp.test", "jkt-x"));
    const decoded = PastaToken.decodeJwt(token);
    expect(decoded.header).toMatchObject({ alg: "EdDSA", typ: "at+jwt", kid: KID });
    expect(decoded.payload).toMatchObject({ sub: "usr_alice_12345" });
    expect(decoded.signingInput).toBe(token.split(".").slice(0, 2).join("."));
    expect(decoded.signature).toHaveLength(64);
  });

  it("throws on anything that is not three JSON-bearing parts", () => {
    expect(() => PastaToken.decodeJwt("a.b")).toThrow(/3 dot-separated/);
    expect(() => PastaToken.decodeJwt("a.b.c.d")).toThrow(/3 dot-separated/);
    expect(() => PastaToken.decodeJwt("!!.!!.!!")).toThrow(/malformed JWT/);
    expect(() => PastaToken.decodeJwt(`${b64u("[1,2]")}.${b64u("{}")}.x`)).toThrow(
      /malformed JWT header/
    );
    expect(() => PastaToken.decodeJwt(`${b64u("{}")}.${b64u('"str"')}.x`)).toThrow(
      /malformed JWT payload/
    );
  });

  it("selects the JWKS entry by kid and ignores unusable entries", () => {
    const jwks = {
      keys: [
        null,
        "not-an-object",
        { kty: "RSA", n: "…", e: "AQAB", kid: KID },
        { kty: "OKP", crv: "X25519", x: "zz", kid: KID },
        ...JWKS.keys,
      ],
    };
    expect(PastaToken.selectJwk(jwks, KID)).toMatchObject({ kid: KID, crv: "Ed25519" });
    expect(PastaToken.selectJwk(jwks, "other-kid")).toBeNull();
    // No kid in the header: unambiguous only when exactly one usable key exists.
    expect(PastaToken.selectJwk(jwks, undefined)).toMatchObject({ kid: KID });
    expect(PastaToken.selectJwk({ keys: [...JWKS.keys, ...JWKS.keys] }, undefined)).toBeNull();
    expect(PastaToken.selectJwk({}, KID)).toBeNull();
    expect(PastaToken.selectJwk(null, KID)).toBeNull();
  });
});

describe("the inline token script: access-token verification", () => {
  const PastaToken = loadPastaToken();
  const ISSUER = "http://idp.test";
  let material: KeyMaterial;

  beforeAll(async () => {
    material = await makeKeyMaterial();
  });

  function expected(overrides: Record<string, unknown> = {}) {
    return { issuer: ISSUER, clientId: ISSUER_CLIENT_ID, jkt: material.jkt, ...overrides };
  }

  it("accepts a token signed by the JWKS key and bound to this key", async () => {
    const token = signAccessToken(accessTokenPayload(ISSUER, material.jkt));
    const result = await PastaToken.verifyAccessToken(token, JWKS, expected());

    expect(result.valid).toBe(true);
    expect(result.error).toBe("");
    expect(result.payload).toMatchObject({ sub: "usr_alice_12345" });
    expect(result.checks.every((c) => c.ok)).toBe(true);
    expect(result.checks.map((c) => c.label)).toEqual([
      "typ = at+jwt",
      "alg = EdDSA",
      "Ed25519 署名",
      "iss",
      "aud に client_id",
      "exp",
      "cnf.jkt = 自鍵の jkt",
    ]);
  });

  it("accepts an aud array that contains the client_id", async () => {
    const token = signAccessToken(
      accessTokenPayload(ISSUER, material.jkt, { aud: ["someone_else", ISSUER_CLIENT_ID] })
    );
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected())).valid).toBe(true);
  });

  it("rejects a payload tampered with after signing", async () => {
    const token = signAccessToken(accessTokenPayload(ISSUER, material.jkt));
    const [headerPart, , signaturePart] = token.split(".");
    const swapped = accessTokenPayload(ISSUER, material.jkt, { sub: "usr_mallory_00000" });
    const tampered = `${headerPart}.${b64u(JSON.stringify(swapped))}.${signaturePart}`;

    const result = await PastaToken.verifyAccessToken(tampered, JWKS, expected());
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Ed25519 signature verification failed");
  });

  it("rejects a token signed by a key that is not in the JWKS", async () => {
    const token = signAccessToken(accessTokenPayload(ISSUER, material.jkt), {
      key: otherKeyPair.privateKey,
    });
    const result = await PastaToken.verifyAccessToken(token, JWKS, expected());
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Ed25519 signature verification failed");
  });

  it("rejects an iss that is not the configured authorization server", async () => {
    const token = signAccessToken(accessTokenPayload("http://evil.test", material.jkt));
    const result = await PastaToken.verifyAccessToken(token, JWKS, expected());
    expect(result.valid).toBe(false);
    expect(result.error).toBe("iss mismatch");
    // The signature check already passed, so the failing row is the iss row.
    expect(result.checks[result.checks.length - 1]).toMatchObject({ label: "iss", ok: false });
  });

  it("rejects an aud that does not contain the client_id", async () => {
    const token = signAccessToken(accessTokenPayload(ISSUER, material.jkt, { aud: "other" }));
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected())).error).toBe(
      "aud mismatch"
    );
  });

  it("rejects an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = signAccessToken(
      accessTokenPayload(ISSUER, material.jkt, { iat: now - 7200, exp: now - 1 })
    );
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected())).error).toBe(
      "token expired"
    );
  });

  it("rejects a non-numeric exp", async () => {
    const token = signAccessToken(accessTokenPayload(ISSUER, material.jkt, { exp: "later" }));
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected())).error).toBe(
      "exp is not a number"
    );
  });

  it("rejects a token bound to somebody else's key", async () => {
    const other = await makeKeyMaterial();
    const token = signAccessToken(accessTokenPayload(ISSUER, other.jkt));
    const result = await PastaToken.verifyAccessToken(token, JWKS, expected());
    expect(result.valid).toBe(false);
    expect(result.error).toBe("cnf.jkt does not match this origin's key");
    expect(result.checks[result.checks.length - 1]).toMatchObject({
      label: "cnf.jkt = 自鍵の jkt",
      ok: false,
      detail: other.jkt,
    });
  });

  it("rejects a token with no cnf.jkt at all", async () => {
    const payload = accessTokenPayload(ISSUER, material.jkt);
    delete payload.cnf;
    const result = await PastaToken.verifyAccessToken(signAccessToken(payload), JWKS, expected());
    expect(result.error).toBe("token carries no cnf.jkt");
  });

  it("rejects a header whose typ is not at+jwt", async () => {
    const token = signAccessToken(accessTokenPayload(ISSUER, material.jkt), {
      header: { typ: "JWT" },
    });
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected())).error).toBe(
      "typ is not at+jwt"
    );
  });

  it("rejects an unknown kid rather than trying every key", async () => {
    const token = signAccessToken(accessTokenPayload(ISSUER, material.jkt), {
      header: { kid: "rotated-away" },
    });
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected())).error).toBe(
      "no JWKS key for kid"
    );
  });

  it("reports a malformed token instead of throwing", async () => {
    const result = await PastaToken.verifyAccessToken("nonsense", JWKS, expected());
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/3 dot-separated/);
  });

  it("honours an injected now, so exp is not wall-clock dependent", async () => {
    const token = signAccessToken(
      accessTokenPayload(ISSUER, material.jkt, { iat: 1000, exp: 2000 })
    );
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected({ now: 1500 }))).valid).toBe(
      true
    );
    expect((await PastaToken.verifyAccessToken(token, JWKS, expected({ now: 2001 }))).error).toBe(
      "token expired"
    );
  });
});

// ---------------------------------------------------------------------------
// Integration against a fake gateway over real HTTP
// ---------------------------------------------------------------------------

interface FakeGateway {
  server: http.Server;
  url: string;
  /** Every `/token` request the script made, as the server saw it. */
  tokenRequests: Array<{
    contentType: string | undefined;
    dpop: string | undefined;
    params: Record<string, string>;
    origin: string | undefined;
  }>;
  jwksHits: number;
  /** When set, `/token` answers with this RFC 6749 error body and a 400. */
  failWith: { error: string; error_description: string } | null;
  /** Issued refresh tokens, newest last — the fake rotates like the contract says. */
  refreshTokens: string[];
}

/**
 * A stand-in for the gateway's `/token` and `/jwks.json`.
 *
 * It verifies the DPoP proof the way section 14.3 says a node does — signature, `htm`,
 * `htu` — and binds the access token to the thumbprint of the proof's own JWK. So a token
 * only comes back if the script really signed with the key it claims to hold.
 */
function startFakeGateway(): Promise<FakeGateway> {
  const state: FakeGateway = {
    server: undefined as unknown as http.Server,
    url: "",
    tokenRequests: [],
    jwksHits: 0,
    failWith: null,
    refreshTokens: [],
  };

  const server = http.createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;

    if (req.method === "GET" && path === "/jwks.json") {
      state.jwksHits++;
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      });
      res.end(JSON.stringify(JWKS));
      return;
    }

    if (req.method === "POST" && path === "/token") {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const params = Object.fromEntries(
          new URLSearchParams(Buffer.concat(chunks).toString("utf8"))
        );
        const proof = req.headers["dpop"] as string | undefined;
        state.tokenRequests.push({
          contentType: req.headers["content-type"],
          dpop: proof,
          params,
          origin: req.headers["origin"] as string | undefined,
        });

        const bad = (error: string, description: string): void => {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error, error_description: description }));
        };

        if (state.failWith) {
          bad(state.failWith.error, state.failWith.error_description);
          return;
        }
        if (!proof) {
          bad("invalid_dpop_proof", "missing DPoP header");
          return;
        }
        const grant = params.grant_type;
        if (grant !== "authorization_code" && grant !== "refresh_token") {
          bad("unsupported_grant_type", `grant_type=${grant}`);
          return;
        }
        if (grant === "authorization_code") {
          // The code is the assertion JWT (section 14, revised). The fake gateway only
          // checks the shape; the real one verifies the group signature via the nodes.
          if (!params.code) {
            bad("invalid_request", "missing code");
            return;
          }
          if (params.code.split(".").length !== 3) {
            bad("invalid_grant", "code is not a JWT-shaped assertion");
            return;
          }
        }
        if (grant === "refresh_token" && !state.refreshTokens.includes(params.refresh_token)) {
          bad("invalid_grant", "unknown or rotated refresh_token");
          return;
        }

        // Verify the proof itself, the way a node would.
        let jkt: string;
        try {
          const [headerPart, payloadPart, signaturePart] = proof.split(".");
          const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
          const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
          if (header.typ !== "dpop+jwt" || header.alg !== "EdDSA") {
            bad("invalid_dpop_proof", "bad proof header");
            return;
          }
          if (payload.htm !== "POST" || payload.htu !== `${state.url}/token`) {
            bad("invalid_dpop_proof", `htm/htu mismatch: ${payload.htm} ${payload.htu}`);
            return;
          }
          const ok = crypto.verify(
            null,
            Buffer.from(`${headerPart}.${payloadPart}`, "ascii"),
            crypto.createPublicKey({ key: header.jwk, format: "jwk" }),
            Buffer.from(signaturePart, "base64url")
          );
          if (!ok) {
            bad("invalid_dpop_proof", "signature check failed");
            return;
          }
          jkt = referenceJkt(header.jwk);
        } catch (err) {
          bad("invalid_dpop_proof", err instanceof Error ? err.message : String(err));
          return;
        }

        const refreshToken = `rt_${crypto.randomBytes(12).toString("base64url")}`;
        state.refreshTokens = [refreshToken]; // rotation: the previous one stops working
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: signAccessToken(accessTokenPayload(state.url, jkt)),
            token_type: "DPoP",
            expires_in: 3600,
            refresh_token: refreshToken,
            scope: "openid profile email",
          })
        );
      });
      return;
    }

    res.writeHead(404).end();
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      state.server = server;
      state.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      resolve(state);
    });
  });
}

describe("the inline token script against a fake gateway", () => {
  const PastaToken = loadPastaToken();
  let gateway: FakeGateway;
  let material: KeyMaterial;
  /** The authorization code: an assertion JWT, several hundred bytes long. */
  const assertion = signAssertion();

  beforeAll(async () => {
    gateway = await startFakeGateway();
    material = await makeKeyMaterial();
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => gateway.server.close(() => resolve()));
  });

  it("exchanges a code for a verified access token", async () => {
    gateway.failWith = null;
    const before = gateway.tokenRequests.length;

    const result = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: {
        grant_type: "authorization_code",
        code: assertion,
        client_id: ISSUER_CLIENT_ID,
        redirect_uri: "http://localhost:3001/callback",
      },
      material,
    })) as {
      ok: boolean;
      tokens: Record<string, unknown>;
      verification: VerifyResult;
    };

    expect(result.ok).toBe(true);
    expect(result.tokens.token_type).toBe("DPoP");
    expect(result.tokens.expires_in).toBe(3600);
    expect(String(result.tokens.refresh_token)).toMatch(/^rt_/);
    expect(result.verification.valid).toBe(true);
    expect(result.verification.payload).toMatchObject({ sub: "usr_alice_12345" });

    // What the gateway actually received: the wire contract the gateway must implement.
    const request = gateway.tokenRequests[before];
    expect(request.contentType).toBe("application/x-www-form-urlencoded");
    expect(request.dpop).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(request.params).toEqual({
      grant_type: "authorization_code",
      code: assertion,
      client_id: ISSUER_CLIENT_ID,
      redirect_uri: "http://localhost:3001/callback",
    });
    expect(gateway.jwksHits).toBeGreaterThan(0);
  });

  it("passes a long assertion JWT through the form body without mangling it", async () => {
    gateway.failWith = null;
    const before = gateway.tokenRequests.length;
    // A realistic assertion: dots, base64url, and long enough that any truncation shows.
    const longAssertion = signAssertion({ scope: "openid profile email".repeat(20) });
    expect(longAssertion.length).toBeGreaterThan(600);

    await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: {
        grant_type: "authorization_code",
        code: longAssertion,
        client_id: ISSUER_CLIENT_ID,
        redirect_uri: "http://localhost:3001/callback",
      },
      material,
    });

    // Form encoding must survive the dots and the length: byte-for-byte equality.
    expect(gateway.tokenRequests[before].params.code).toBe(longAssertion);
  });

  it("surfaces the gateway's refusal of a code that is not assertion-shaped", async () => {
    gateway.failWith = null;
    const result = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: {
        grant_type: "authorization_code",
        code: "opaque_handle_from_the_old_design",
        client_id: ISSUER_CLIENT_ID,
        redirect_uri: "http://localhost:3001/callback",
      },
      material,
    })) as { ok: boolean; error: string; errorDescription: string };

    expect(result.ok).toBe(false);
    expect(result.error).toBe("invalid_grant");
    expect(result.errorDescription).toBe("code is not a JWT-shaped assertion");
  });

  it("refreshes with a new proof and a rotated refresh_token", async () => {
    gateway.failWith = null;
    const first = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: {
        grant_type: "authorization_code",
        code: assertion,
        client_id: ISSUER_CLIENT_ID,
        redirect_uri: "http://localhost:3001/callback",
      },
      material,
    })) as { ok: boolean; tokens: Record<string, string> };
    const staleRefreshToken = first.tokens.refresh_token;

    const refreshed = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: { grant_type: "refresh_token", refresh_token: staleRefreshToken },
      material,
    })) as { ok: boolean; tokens: Record<string, string>; verification: VerifyResult };

    expect(refreshed.ok).toBe(true);
    expect(refreshed.verification.valid).toBe(true);
    expect(refreshed.tokens.refresh_token).not.toBe(staleRefreshToken);

    // Each request carried its own proof with its own jti.
    const proofs = gateway.tokenRequests.slice(-2).map((r) => r.dpop as string);
    expect(proofs[0]).not.toBe(proofs[1]);
    const jtis = proofs.map(
      (p) => JSON.parse(Buffer.from(p.split(".")[1], "base64url").toString("utf8")).jti
    );
    expect(jtis[0]).not.toBe(jtis[1]);

    // The rotated-away token is refused, and the script surfaces the RFC 6749 body.
    const reused = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: { grant_type: "refresh_token", refresh_token: staleRefreshToken },
      material,
    })) as { ok: boolean; error: string; errorDescription: string };
    expect(reused.ok).toBe(false);
    expect(reused.error).toBe("invalid_grant");
    expect(reused.errorDescription).toBe("unknown or rotated refresh_token");
  });

  it("surfaces a 400 from /token as its error and error_description", async () => {
    gateway.failWith = { error: "invalid_grant", error_description: "code already used" };

    const result = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: {
        grant_type: "authorization_code",
        code: assertion,
        client_id: ISSUER_CLIENT_ID,
        redirect_uri: "http://localhost:3001/callback",
      },
      material,
    })) as { ok: boolean; stage: string; status: number; error: string; errorDescription: string };

    expect(result.ok).toBe(false);
    expect(result.stage).toBe("token");
    expect(result.status).toBe(400);
    expect(result.error).toBe("invalid_grant");
    expect(result.errorDescription).toBe("code already used");
    gateway.failWith = null;
  });

  it("is refused when the DPoP header is stripped in flight", async () => {
    // Stands in for a client that forgot the proof: the gateway must not issue.
    const strippingFetch: typeof fetch = (input, init) => {
      const headers = new Headers(init?.headers);
      headers.delete("DPoP");
      return fetch(input as string, { ...init, headers });
    };

    const result = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: {
        grant_type: "authorization_code",
        code: assertion,
        client_id: ISSUER_CLIENT_ID,
        redirect_uri: "http://localhost:3001/callback",
      },
      material,
      fetchImpl: strippingFetch,
    })) as { ok: boolean; error: string };

    expect(result.ok).toBe(false);
    expect(result.error).toBe("invalid_dpop_proof");
  });

  it("reports an unreachable JWKS without losing the token it already has", async () => {
    const onlyTokenFetch: typeof fetch = (input, init) => {
      const url = String(input);
      if (url.endsWith("/jwks.json")) return Promise.reject(new Error("ECONNREFUSED"));
      return fetch(url, init);
    };

    const result = (await PastaToken.obtainToken({
      issuer: gateway.url,
      clientId: ISSUER_CLIENT_ID,
      grantParams: {
        grant_type: "authorization_code",
        code: assertion,
        client_id: ISSUER_CLIENT_ID,
        redirect_uri: "http://localhost:3001/callback",
      },
      material,
      fetchImpl: onlyTokenFetch,
    })) as { ok: boolean; stage: string; error: string; tokens: Record<string, string> };

    expect(result.ok).toBe(false);
    expect(result.stage).toBe("jwks");
    expect(result.error).toBe("jwks_unreachable");
    expect(result.tokens.access_token).toBeTruthy();
  });
});
