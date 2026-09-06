/**
 * HTML for the two rp pages, plus the inline JavaScript they carry.
 *
 * docs/container-split.md section 14: the rp server serves HTML and nothing else. The
 * authorization code is exchanged at `<ISSUER>/token` by the browser, with a DPoP proof
 * signed by a key that lives only in this origin's IndexedDB (section 13), and the
 * resulting access token is verified in the browser against `<ISSUER>/jwks.json`. So the
 * interesting code in this file is the inline JS, not the markup.
 *
 * The inline scripts are written with no build step and no runtime dependency: ES5-style
 * `var`/`function` plus `async`/`await`, string concatenation instead of template
 * literals (a template literal cannot survive being embedded in this one), and no `${`
 * sequence anywhere. Each exposes a namespace object and does nothing on load, so
 * `tests/token-script.test.ts` can pull it out with `new Function` and run it under
 * Node's WebCrypto.
 */

/** Escapes text before interpolation so untrusted values can never inject markup. */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SHARED_HEAD_STYLE = `
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f8fafc;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: #fff;
      border-bottom: 1px solid #e2e8f0;
      padding: 0 2rem;
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    header .logo { font-weight: 700; font-size: 1.1rem; color: #1e293b; letter-spacing: -0.02em; }
    footer {
      text-align: center;
      padding: 1.5rem;
      font-size: 0.75rem;
      color: #94a3b8;
      border-top: 1px solid #e2e8f0;
    }`;

/**
 * The DPoP key store both rp pages inline.
 *
 * docs/container-split.md section 13: the DPoP key pair belongs to the rp front end.
 * The private key is generated non-extractable with WebCrypto and kept in this origin's
 * IndexedDB, so it never reaches the rp server, the gateway, the demo UI or a node. Only
 * the RFC 7638 thumbprint of the public key travels, as `dpop_jkt` on `/authorize` — and
 * later, implicitly, as the `jwk` header of a DPoP proof.
 *
 * The thumbprint must match `calculateJwkThumbprint` on the node side byte for byte:
 * SHA-256 over `{"crv":...,"kty":...,"x":...}` with the three members in lexicographic
 * order and no whitespace, base64url encoded without padding.
 */
export const DPOP_SCRIPT = `
var PastaDpop = (function () {
  "use strict";

  var DB_NAME = "pasta-rp";
  var STORE_NAME = "dpop";
  var KEY_NAME = "current";

  function bytesToBase64Url(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }

  /** RFC 7638 JWK thumbprint of an OKP/Ed25519 public JWK. */
  async function jktFromJwk(jwk) {
    var canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
    var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return bytesToBase64Url(new Uint8Array(digest));
  }

  function generateKeyPair() {
    return crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  }

  function openDb() {
    return new Promise(function (resolve, reject) {
      var request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = function () {
        var db = request.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
      request.onsuccess = function () { resolve(request.result); };
      request.onerror = function () { reject(request.error); };
      request.onblocked = function () { reject(new Error("IndexedDB open blocked")); };
    });
  }

  function idbGet(db, key) {
    return new Promise(function (resolve, reject) {
      var request = db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(key);
      request.onsuccess = function () { resolve(request.result); };
      request.onerror = function () { reject(request.error); };
    });
  }

  function idbPut(db, key, value) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(value, key);
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
      tx.onabort = function () { reject(tx.error); };
    });
  }

  /** The stored key pair, or a freshly generated and stored one. */
  async function ensureKeyPair() {
    var db = await openDb();
    try {
      var stored = await idbGet(db, KEY_NAME);
      if (stored && stored.privateKey && stored.publicKey) {
        return stored;
      }
      var pair = await generateKeyPair();
      await idbPut(db, KEY_NAME, { privateKey: pair.privateKey, publicKey: pair.publicKey });
      return pair;
    } finally {
      db.close();
    }
  }

  /**
   * Everything the token flow needs from the key store: the non-extractable signing key,
   * the three JWK members that go in a DPoP proof header, and their thumbprint.
   */
  async function ensureKeyMaterial() {
    var pair = await ensureKeyPair();
    var exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
    var publicJwk = { crv: exported.crv, kty: exported.kty, x: exported.x };
    var jkt = await jktFromJwk(publicJwk);
    return { privateKey: pair.privateKey, publicJwk: publicJwk, jkt: jkt };
  }

  /** The thumbprint of the stored key, recomputed on every page load. */
  async function ensureJkt() {
    var material = await ensureKeyMaterial();
    return material.jkt;
  }

  function unavailableReason() {
    if (typeof crypto === "undefined" || !crypto.subtle) {
      return "このブラウザには WebCrypto (crypto.subtle) がありません。";
    }
    if (typeof indexedDB === "undefined") {
      return "このブラウザでは IndexedDB を使えません。";
    }
    return "";
  }

  return {
    jktFromJwk: jktFromJwk,
    ensureKeyPair: ensureKeyPair,
    ensureKeyMaterial: ensureKeyMaterial,
    ensureJkt: ensureJkt,
    unavailableReason: unavailableReason
  };
})();
`;

/**
 * The token flow: DPoP proof, `POST /token`, JWKS fetch, access-token verification.
 *
 * Everything here is a pure function of its arguments plus WebCrypto. IndexedDB access
 * (`material`) and network access (`fetchImpl`) are parameters, not globals, which is
 * what lets `tests/token-script.test.ts` run the whole flow under Node against a fake
 * gateway on port 0. `PastaToken` touches no DOM at all; the page glue below does that.
 */
export const TOKEN_SCRIPT = `
var PastaToken = (function () {
  "use strict";

  function bytesToBase64Url(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }

  function textToBase64Url(text) {
    return bytesToBase64Url(new TextEncoder().encode(text));
  }

  function base64UrlToBytes(value) {
    var normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4 !== 0) {
      normalized += "=";
    }
    var binary = atob(normalized);
    var out = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  function base64UrlToText(value) {
    return new TextDecoder().decode(base64UrlToBytes(value));
  }

  /** 128 random bits, base64url. Used for the proof jti and the OAuth state. */
  function randomId() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return bytesToBase64Url(bytes);
  }

  function nowSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  /**
   * RFC 9449 DPoP proof for one request.
   *
   * Header carries the public JWK so the receiver can thumbprint it and compare with the
   * jkt bound to the session; the private key is non-extractable and only ever signs.
   */
  async function createProof(material, params) {
    var header = {
      typ: "dpop+jwt",
      alg: "EdDSA",
      jwk: {
        kty: material.publicJwk.kty,
        crv: material.publicJwk.crv,
        x: material.publicJwk.x
      }
    };
    var payload = {
      jti: params && params.jti ? params.jti : randomId(),
      htm: params.htm,
      htu: params.htu,
      iat: params && typeof params.iat === "number" ? params.iat : nowSeconds()
    };
    var signingInput =
      textToBase64Url(JSON.stringify(header)) + "." + textToBase64Url(JSON.stringify(payload));
    var signature = await crypto.subtle.sign(
      "Ed25519",
      material.privateKey,
      new TextEncoder().encode(signingInput)
    );
    return signingInput + "." + bytesToBase64Url(new Uint8Array(signature));
  }

  /** Splits a compact JWS and parses the two JSON parts. Throws on anything malformed. */
  function decodeJwt(token) {
    var parts = String(token).split(".");
    if (parts.length !== 3) {
      throw new Error("malformed JWT: expected 3 dot-separated parts");
    }
    var header;
    var payload;
    try {
      header = JSON.parse(base64UrlToText(parts[0]));
    } catch (err) {
      throw new Error("malformed JWT header");
    }
    try {
      payload = JSON.parse(base64UrlToText(parts[1]));
    } catch (err) {
      throw new Error("malformed JWT payload");
    }
    if (!header || typeof header !== "object" || Array.isArray(header)) {
      throw new Error("malformed JWT header");
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("malformed JWT payload");
    }
    return {
      header: header,
      payload: payload,
      signingInput: parts[0] + "." + parts[1],
      signature: base64UrlToBytes(parts[2])
    };
  }

  /** Picks the Ed25519 JWKS entry named by the token header's kid. */
  function selectJwk(jwks, kid) {
    var keys = jwks && Array.isArray(jwks.keys) ? jwks.keys : [];
    var usable = [];
    for (var i = 0; i < keys.length; i++) {
      var candidate = keys[i];
      if (!candidate || typeof candidate !== "object") continue;
      if (candidate.kty !== "OKP" || candidate.crv !== "Ed25519") continue;
      if (typeof candidate.x !== "string") continue;
      if (candidate.alg !== undefined && candidate.alg !== "EdDSA") continue;
      usable.push(candidate);
    }
    if (kid !== undefined && kid !== null && kid !== "") {
      for (var j = 0; j < usable.length; j++) {
        if (usable[j].kid === kid) return usable[j];
      }
      return null;
    }
    return usable.length === 1 ? usable[0] : null;
  }

  async function verifySignature(decoded, jwk) {
    var key = await crypto.subtle.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", x: jwk.x },
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return crypto.subtle.verify(
      "Ed25519",
      key,
      decoded.signature,
      new TextEncoder().encode(decoded.signingInput)
    );
  }

  function audienceList(aud) {
    if (Array.isArray(aud)) return aud.map(String);
    if (aud === undefined || aud === null) return [];
    return [String(aud)];
  }

  /**
   * Checks the access token the way a resource server would, in the browser.
   *
   * Returns every check it made, in order, so the page can show a row per check rather
   * than a single pass/fail. The first failure stops the chain: there is nothing useful
   * to say about \`iss\` on a token whose signature did not verify.
   */
  async function verifyAccessToken(accessToken, jwks, expected) {
    var now = expected && typeof expected.now === "number" ? expected.now : nowSeconds();
    var checks = [];
    function add(label, ok, detail) {
      checks.push({ label: label, ok: ok, detail: detail === undefined ? "" : String(detail) });
    }
    function fail(error) {
      return { valid: false, error: error, checks: checks, header: null, payload: null };
    }

    var decoded;
    try {
      decoded = decodeJwt(accessToken);
    } catch (err) {
      add("JWT の形式", false, err && err.message ? err.message : String(err));
      return fail(err && err.message ? err.message : String(err));
    }

    function failWith(error, label, detail) {
      add(label, false, detail);
      return {
        valid: false,
        error: error,
        checks: checks,
        header: decoded.header,
        payload: decoded.payload
      };
    }

    if (decoded.header.typ !== "at+jwt") {
      return failWith("typ is not at+jwt", "typ = at+jwt", String(decoded.header.typ));
    }
    add("typ = at+jwt", true, "at+jwt");

    if (decoded.header.alg !== "EdDSA") {
      return failWith("alg is not EdDSA", "alg = EdDSA", String(decoded.header.alg));
    }
    add("alg = EdDSA", true, "EdDSA");

    var jwk = selectJwk(jwks, decoded.header.kid);
    if (!jwk) {
      return failWith(
        "no JWKS key for kid",
        "JWKS の鍵 (kid)",
        decoded.header.kid ? String(decoded.header.kid) : "(kid なし)"
      );
    }

    var signatureOk = false;
    try {
      signatureOk = await verifySignature(decoded, jwk);
    } catch (err) {
      return failWith(
        "signature verification error",
        "Ed25519 署名",
        err && err.message ? err.message : String(err)
      );
    }
    if (!signatureOk) {
      return failWith("Ed25519 signature verification failed", "Ed25519 署名", "検証失敗");
    }
    add("Ed25519 署名", true, "kid=" + (decoded.header.kid ? String(decoded.header.kid) : "-"));

    if (String(decoded.payload.iss) !== String(expected.issuer)) {
      return failWith("iss mismatch", "iss", String(decoded.payload.iss));
    }
    add("iss", true, String(decoded.payload.iss));

    var auds = audienceList(decoded.payload.aud);
    if (auds.indexOf(String(expected.clientId)) === -1) {
      return failWith("aud mismatch", "aud に client_id", auds.join(",") || "(なし)");
    }
    add("aud に client_id", true, auds.join(","));

    if (typeof decoded.payload.exp !== "number") {
      return failWith("exp is not a number", "exp", String(decoded.payload.exp));
    }
    if (decoded.payload.exp <= now) {
      return failWith("token expired", "exp", "期限切れ");
    }
    add("exp", true, "残り " + (decoded.payload.exp - now) + "s");

    var cnf = decoded.payload.cnf;
    var tokenJkt = cnf && typeof cnf === "object" && typeof cnf.jkt === "string" ? cnf.jkt : "";
    if (!tokenJkt) {
      return failWith("token carries no cnf.jkt", "cnf.jkt = 自鍵の jkt", "(なし)");
    }
    if (tokenJkt !== String(expected.jkt)) {
      return failWith("cnf.jkt does not match this origin's key", "cnf.jkt = 自鍵の jkt", tokenJkt);
    }
    add("cnf.jkt = 自鍵の jkt", true, tokenJkt);

    return {
      valid: true,
      error: "",
      checks: checks,
      header: decoded.header,
      payload: decoded.payload
    };
  }

  function formEncode(params) {
    var body = new URLSearchParams();
    for (var name in params) {
      if (Object.prototype.hasOwnProperty.call(params, name) && params[name] !== undefined) {
        body.set(name, String(params[name]));
      }
    }
    return body.toString();
  }

  /**
   * One \`POST /token\` with a fresh DPoP proof.
   *
   * A non-2xx answer is not an exception: RFC 6749 error bodies are the normal way the
   * authorization server says "that code is spent", and the page shows them verbatim.
   */
  async function requestToken(options) {
    var fetchImpl = options.fetchImpl || fetch;
    var proof = await createProof(options.material, {
      htm: "POST",
      htu: options.tokenEndpoint,
      iat: options.now,
      jti: options.jti
    });
    var response = await fetchImpl(options.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: proof
      },
      body: formEncode(options.params)
    });
    var text = await response.text();
    var json = null;
    try {
      json = JSON.parse(text);
    } catch (err) {
      json = null;
    }
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: json && json.error ? String(json.error) : "http_" + response.status,
        errorDescription:
          json && json.error_description ? String(json.error_description) : text.slice(0, 300),
        proof: proof
      };
    }
    if (!json || typeof json.access_token !== "string") {
      return {
        ok: false,
        status: response.status,
        error: "invalid_token_response",
        errorDescription: "no access_token in the /token response",
        proof: proof
      };
    }
    return { ok: true, status: response.status, tokens: json, proof: proof };
  }

  async function fetchJwks(options) {
    var fetchImpl = options.fetchImpl || fetch;
    var response = await fetchImpl(options.jwksUri, { method: "GET" });
    if (!response.ok) {
      throw new Error("JWKS fetch failed: HTTP " + response.status);
    }
    return response.json();
  }

  /**
   * The whole browser side of section 14 step 10-13: exchange, fetch JWKS, verify.
   *
   * \`grantParams\` is the only difference between the first exchange
   * (\`grant_type=authorization_code\`) and a refresh (\`grant_type=refresh_token\`), which is
   * why both go through this one function with a proof each.
   */
  async function obtainToken(options) {
    var result = await requestToken({
      tokenEndpoint: options.issuer + "/token",
      params: options.grantParams,
      material: options.material,
      fetchImpl: options.fetchImpl,
      now: options.now,
      jti: options.jti
    });
    if (!result.ok) {
      return {
        ok: false,
        stage: "token",
        error: result.error,
        errorDescription: result.errorDescription,
        status: result.status
      };
    }
    var jwks;
    try {
      jwks = await fetchJwks({
        jwksUri: options.issuer + "/jwks.json",
        fetchImpl: options.fetchImpl
      });
    } catch (err) {
      return {
        ok: false,
        stage: "jwks",
        error: "jwks_unreachable",
        errorDescription: err && err.message ? err.message : String(err),
        tokens: result.tokens
      };
    }
    var verification = await verifyAccessToken(result.tokens.access_token, jwks, {
      issuer: options.issuer,
      clientId: options.clientId,
      jkt: options.material.jkt,
      now: options.now
    });
    return { ok: true, stage: "verified", tokens: result.tokens, verification: verification };
  }

  return {
    bytesToBase64Url: bytesToBase64Url,
    textToBase64Url: textToBase64Url,
    base64UrlToBytes: base64UrlToBytes,
    base64UrlToText: base64UrlToText,
    randomId: randomId,
    createProof: createProof,
    decodeJwt: decodeJwt,
    selectJwk: selectJwk,
    verifyAccessToken: verifyAccessToken,
    requestToken: requestToken,
    fetchJwks: fetchJwks,
    obtainToken: obtainToken
  };
})();
`;

/** Where the landing page parks the `state` it is about to send to `/authorize`. */
export const STATE_STORAGE_KEY = "pasta-rp-state";

/**
 * Landing-page glue: resolve the DPoP thumbprint, remember `state`, then arm the link.
 *
 * The anchor ships without an `href` and with `aria-disabled="true"`, so the login button
 * is inert until `dpop_jkt` is known. `/authorize` rejects a request without it
 * (contract section 6), so an armed link is the only link worth offering.
 *
 * `state` is stored in sessionStorage before the navigation, and `/callback` compares the
 * value the authorization server echoes against it. That check is the browser's, because
 * the rp server keeps no per-request state at all.
 */
const LANDING_SCRIPT = `
(function () {
  "use strict";
  var button = document.getElementById("login-btn");
  var label = document.getElementById("login-label");
  var output = document.getElementById("dpop-jkt");
  var reason = document.getElementById("dpop-reason");
  var authorizeUrl = button.getAttribute("data-authorize-url");
  var state = button.getAttribute("data-state");

  function unavailable(message) {
    output.textContent = "(未生成)";
    label.textContent = "ログインできません";
    reason.textContent = message;
  }

  var blocked = PastaDpop.unavailableReason();
  if (blocked) {
    unavailable(blocked);
    return;
  }

  try {
    sessionStorage.setItem("pasta-rp-state", state);
  } catch (err) {
    // A blocked sessionStorage only costs the callback its state check; say so there.
  }

  PastaDpop.ensureJkt().then(function (jkt) {
    output.textContent = jkt;
    button.setAttribute("href", authorizeUrl + "&dpop_jkt=" + encodeURIComponent(jkt));
    button.removeAttribute("aria-disabled");
    label.textContent = "PASTA IdP でログイン";
  }).catch(function (err) {
    unavailable(
      "この環境の WebCrypto は Ed25519 の DPoP 鍵を作成できませんでした: " +
        (err && err.message ? err.message : String(err))
    );
  });
})();
`;

export interface LandingParams {
  authorizeUrl: string;
  /** The `state` embedded in `authorizeUrl`; the page stores it for the callback check. */
  state: string;
}

/** The ZK-App Portal landing page: a third-party service offering IdP login. */
export function renderLandingPage(params: LandingParams): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>ZK-App Portal</title>
  <style>${SHARED_HEAD_STYLE}
    header nav a { color: #64748b; text-decoration: none; font-size: 0.875rem; margin-left: 1.5rem; }
    header nav a:hover { color: #1e293b; }
    main {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 4rem 1rem;
    }
    .hero { text-align: center; max-width: 520px; }
    .hero h1 { font-size: 2rem; font-weight: 800; color: #0f172a; margin: 0 0 1rem; line-height: 1.2; }
    .hero p { color: #64748b; font-size: 1rem; line-height: 1.6; margin: 0 0 2.5rem; }
    .login-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.625rem;
      background: #4f46e5;
      color: #fff;
      font-size: 0.9375rem;
      font-weight: 600;
      padding: 0.75rem 1.75rem;
      border-radius: 8px;
      text-decoration: none;
      transition: background 0.15s;
    }
    .login-btn:hover { background: #4338ca; }
    .login-btn svg { flex-shrink: 0; }
    .badge {
      display: inline-block;
      background: #ede9fe;
      color: #6d28d9;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.25rem 0.75rem;
      border-radius: 100px;
      margin-bottom: 1.5rem;
      letter-spacing: 0.03em;
    }
    .features {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1rem;
      max-width: 640px;
      margin: 3rem 0 0;
    }
    .feature {
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      padding: 1rem;
      font-size: 0.8125rem;
      color: #475569;
      text-align: center;
    }
    .feature strong { display: block; color: #1e293b; font-size: 0.875rem; margin-bottom: 0.25rem; }
    .login-btn[aria-disabled="true"] {
      background: #cbd5e1;
      color: #64748b;
      cursor: progress;
      pointer-events: none;
    }
    .dpop {
      margin-top: 1.75rem;
      font-size: 0.8125rem;
      color: #475569;
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 0.75rem 1rem;
      text-align: left;
    }
    .dpop code {
      font-family: ui-monospace, monospace;
      font-size: 0.75rem;
      color: #1e293b;
      word-break: break-all;
    }
    .dpop .reason { display: block; margin-top: 0.5rem; color: #b91c1c; }
    .dpop .reason:empty { display: none; }
  </style>
</head>
<body>
  <header>
    <span class="logo">ZK-App Portal</span>
    <nav>
      <a href="#">機能</a>
      <a href="#">料金</a>
      <a href="#">ドキュメント</a>
    </nav>
  </header>
  <main>
    <div class="hero">
      <span class="badge">分散型 ID 対応サービス</span>
      <h1>ZK-App Portal へようこそ</h1>
      <p>このサービスは PASTA 分散 IdP による OAuth 2.0 認可コードフロー (DPoP) に対応しています。<br>
         認可サーバーは平文トークンを保持せず、ブラウザが端末内で署名を集約します。</p>
      <a class="login-btn" id="login-btn" aria-disabled="true"
         data-authorize-url="${escapeHtml(params.authorizeUrl)}"
         data-state="${escapeHtml(params.state)}">
        <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0zM3 20a9 9 0 0 1 18 0"/>
        </svg>
        <span id="login-label">DPoP 鍵を準備中...</span>
      </a>
      <div class="dpop">
        my DPoP jkt: <code id="dpop-jkt">(生成中)</code>
        <span class="reason" id="dpop-reason"></span>
      </div>
    </div>
    <div class="features">
      <div class="feature"><strong>秘密分散鍵</strong>単一障害点なし</div>
      <div class="feature"><strong>ゼロ知識プロキシ</strong>AS はトークンを持たない</div>
      <div class="feature"><strong>標準 OAuth + DPoP</strong>RP 側の改修不要</div>
    </div>
  </main>
  <footer>ZK-App Portal (RP デモ) — PASTA + FROST + OAuth Proxy</footer>
  <script>${DPOP_SCRIPT}</script>
  <script>${LANDING_SCRIPT}</script>
</body>
</html>`;
}

/**
 * Callback-page glue: state check, `/token`, verification, rendering, refresh button.
 *
 * Every value that came from outside — the code, the token, its claims, an error body —
 * reaches the DOM through `textContent`, never `innerHTML`, so nothing the authorization
 * server returns can become markup.
 */
const TOKEN_PAGE_SCRIPT = `
(function () {
  "use strict";
  var root = document.getElementById("token-flow");
  var issuer = root.getAttribute("data-issuer");
  var clientId = root.getAttribute("data-client-id");
  var redirectUri = root.getAttribute("data-redirect-uri");
  var code = root.getAttribute("data-code");
  var state = root.getAttribute("data-state");

  var statusEl = document.getElementById("flow-status");
  var detailEl = document.getElementById("flow-detail");
  var resultEl = document.getElementById("flow-result");
  var accessTokenEl = document.getElementById("access-token");
  var tokenTypeEl = document.getElementById("token-type");
  var expiresInEl = document.getElementById("expires-in");
  var scopeEl = document.getElementById("token-scope");
  var refreshTokenEl = document.getElementById("refresh-token");
  var myJktEl = document.getElementById("my-dpop-jkt");
  var checksEl = document.getElementById("verify-checks");
  var claimsEl = document.getElementById("token-claims");
  var refreshBtn = document.getElementById("refresh-btn");

  var material = null;
  var refreshToken = "";

  function setStatus(text, ok) {
    statusEl.textContent = text;
    statusEl.className = ok ? "banner ok" : "banner ng";
  }

  function setDetail(text) {
    detailEl.textContent = text || "";
  }

  function fail(text, detail) {
    setStatus("✖ " + text, false);
    setDetail(detail || "");
    refreshBtn.disabled = true;
  }

  function renderChecks(checks) {
    checksEl.textContent = "";
    for (var i = 0; i < checks.length; i++) {
      var item = document.createElement("li");
      item.className = checks[i].ok ? "check-ok" : "check-ng";
      item.textContent =
        (checks[i].ok ? "✓ " : "✖ ") +
        checks[i].label +
        (checks[i].detail ? " — " + checks[i].detail : "");
      checksEl.appendChild(item);
    }
  }

  function renderResult(result) {
    var tokens = result.tokens;
    resultEl.hidden = false;
    accessTokenEl.textContent = tokens.access_token;
    tokenTypeEl.textContent = tokens.token_type ? String(tokens.token_type) : "(なし)";
    expiresInEl.textContent =
      tokens.expires_in === undefined ? "(なし)" : String(tokens.expires_in) + "s";
    scopeEl.textContent = tokens.scope ? String(tokens.scope) : "(なし)";
    if (typeof tokens.refresh_token === "string" && tokens.refresh_token) {
      refreshToken = tokens.refresh_token;
      refreshTokenEl.textContent = refreshToken.slice(0, 8) + " (先頭 8 文字)";
      refreshBtn.disabled = false;
    } else {
      refreshToken = "";
      refreshTokenEl.textContent = "(なし)";
      refreshBtn.disabled = true;
    }
    myJktEl.textContent = material.jkt;
    renderChecks(result.verification.checks);
    claimsEl.textContent = result.verification.payload
      ? JSON.stringify(result.verification.payload, null, 2)
      : "(クレームを解析できませんでした)";
    if (result.verification.valid) {
      setStatus("✓ アクセストークンを取得し、ブラウザ内で検証しました", true);
      setDetail("署名・iss・aud・exp・cnf.jkt をすべてこのページで確認しています。");
    } else {
      setStatus("✖ トークン検証に失敗しました: " + result.verification.error, false);
      setDetail("");
    }
  }

  async function run(grantParams, pendingText) {
    setStatus(pendingText, true);
    setDetail("");
    refreshBtn.disabled = true;
    try {
      var result = await PastaToken.obtainToken({
        issuer: issuer,
        clientId: clientId,
        grantParams: grantParams,
        material: material
      });
      if (!result.ok) {
        fail(result.error, result.errorDescription);
        if (refreshToken) refreshBtn.disabled = false;
        return;
      }
      renderResult(result);
    } catch (err) {
      fail("token_flow_error", err && err.message ? err.message : String(err));
    }
  }

  refreshBtn.addEventListener("click", function () {
    if (!refreshToken) return;
    run({ grant_type: "refresh_token", refresh_token: refreshToken }, "リフレッシュ中...");
  });

  var blocked = PastaDpop.unavailableReason();
  if (blocked) {
    fail("browser_unsupported", blocked);
    return;
  }

  var expectedState = null;
  try {
    expectedState = sessionStorage.getItem("pasta-rp-state");
  } catch (err) {
    expectedState = null;
  }
  if (expectedState === null) {
    fail(
      "state_missing",
      "このブラウザに state が保存されていません。/ から始めてください (sessionStorage が無効の可能性もあります)。"
    );
    return;
  }
  if (expectedState !== state) {
    fail("state_mismatch", "認可サーバーが返した state がこのブラウザの値と一致しません。");
    return;
  }

  PastaDpop.ensureKeyMaterial().then(function (loaded) {
    material = loaded;
    myJktEl.textContent = loaded.jkt;
    return run(
      {
        // \`code\` is the assertion JWT, passed through untouched.
        grant_type: "authorization_code",
        code: code,
        client_id: clientId,
        redirect_uri: redirectUri
      },
      "認可コードをアクセストークンに交換中..."
    );
  }).catch(function (err) {
    fail("dpop_key_unavailable", err && err.message ? err.message : String(err));
  });
})();
`;

export interface CallbackParams {
  /**
   * The authorization code from the query string: the authentication assertion JWT
   * itself (contract section 14, revised). Long, but handled as one opaque string.
   */
  code: string;
  /** The `state` the authorization server echoed. The page compares it with sessionStorage. */
  state: string;
  /** Authorization server base URL: the page appends `/token` and `/jwks.json`. */
  issuer: string;
  clientId: string;
  /** The exact `redirect_uri` used at `/authorize`; `/token` requires it again. */
  redirectUri: string;
}

const CALLBACK_STYLE = `
    main { flex: 1; display: flex; flex-direction: column; align-items: center; padding: 3rem 1rem; }
    .card {
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 2rem;
      max-width: 720px;
      width: 100%;
      box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    .banner {
      border-radius: 8px;
      padding: 0.875rem 1rem;
      margin-bottom: 0.75rem;
      font-weight: 600;
      font-size: 0.9375rem;
    }
    .banner.ok { background: #f0fdf4; border: 1px solid #bbf7d0; color: #15803d; }
    .banner.ng { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
    .detail { font-size: 0.8125rem; color: #64748b; margin: 0 0 1.5rem; line-height: 1.6; word-break: break-all; }
    h2 { font-size: 1.125rem; color: #0f172a; margin: 1.5rem 0 0.75rem; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th, td { text-align: left; padding: 0.5rem 0.625rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
    th { color: #64748b; font-weight: 500; width: 34%; }
    td { color: #1e293b; font-family: ui-monospace, monospace; font-size: 0.8125rem; word-break: break-all; }
    ul.checks { list-style: none; padding: 0; margin: 0; font-size: 0.875rem; }
    ul.checks li { padding: 0.3rem 0; border-bottom: 1px solid #f1f5f9; }
    .check-ok { color: #15803d; }
    .check-ng { color: #b91c1c; }
    pre { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.875rem; font-size: 0.75rem; overflow-x: auto; color: #334155; margin: 0.5rem 0 0; }
    summary { cursor: pointer; color: #6366f1; font-size: 0.875rem; font-weight: 500; padding: 0.5rem 0; }
    button {
      background: #4f46e5; color: #fff; border: 0; border-radius: 8px;
      padding: 0.55rem 1.25rem; font-size: 0.875rem; font-weight: 600; cursor: pointer;
      margin-top: 1.25rem;
    }
    button:disabled { background: #cbd5e1; color: #64748b; cursor: not-allowed; }
    .back { display: inline-block; margin-top: 1.5rem; margin-right: 1.25rem; color: #6366f1; font-size: 0.875rem; font-weight: 500; text-decoration: none; }
    .back:hover { text-decoration: underline; }
    .note { font-size: 0.75rem; color: #94a3b8; margin-top: 1rem; line-height: 1.5; }`;

/**
 * The post-redirect page. The server fills in nothing but the five `data-` attributes;
 * everything visible is written by `TOKEN_PAGE_SCRIPT` after it has called `/token`.
 */
export function renderCallbackPage(params: CallbackParams): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>ZK-App Portal - トークン取得</title>
  <style>${SHARED_HEAD_STYLE}${CALLBACK_STYLE}
  </style>
</head>
<body>
  <header>
    <span class="logo">ZK-App Portal</span>
    <span style="font-size:0.8125rem;color:#64748b">OAuth 2.0 authorization code + DPoP</span>
  </header>
  <main id="token-flow"
        data-code="${escapeHtml(params.code)}"
        data-state="${escapeHtml(params.state)}"
        data-issuer="${escapeHtml(params.issuer)}"
        data-client-id="${escapeHtml(params.clientId)}"
        data-redirect-uri="${escapeHtml(params.redirectUri)}">
    <div class="card">
      <div class="banner ok" id="flow-status">DPoP 鍵を読み出し中...</div>
      <p class="detail" id="flow-detail"></p>

      <div id="flow-result" hidden>
        <h2>アクセストークン</h2>
        <table>
          <tr><th>access_token</th><td id="access-token"></td></tr>
          <tr><th>token_type</th><td id="token-type"></td></tr>
          <tr><th>expires_in</th><td id="expires-in"></td></tr>
          <tr><th>scope</th><td id="token-scope"></td></tr>
          <tr><th>refresh_token</th><td id="refresh-token"></td></tr>
          <tr><th>my DPoP jkt (この端末)</th><td id="my-dpop-jkt">(読み出し中)</td></tr>
        </table>

        <h2>ブラウザ内での検証</h2>
        <ul class="checks" id="verify-checks"></ul>

        <details>
          <summary>クレーム (生データ)</summary>
          <pre id="token-claims"></pre>
        </details>
      </div>

      <button id="refresh-btn" type="button" disabled>リフレッシュ</button>

      <p class="note">
        rp サーバーは HTML を返しただけです。<code>/token</code> の呼び出し、DPoP proof の署名、
        JWKS の取得と Ed25519 検証はすべてこのページの JavaScript が行っています。<br>
        受け取った認可コードは認証アサーション (ノードのグループ署名 JWT) そのもので、rp は
        中身を解釈せずそのまま <code>/token</code> に渡します。検証するのは gateway とノードです。<br>
        DPoP 秘密鍵は extractable=false でこのオリジンの IndexedDB にあり、サーバーには渡りません。
      </p>
      <a class="back" href="/">← ZK-App Portal トップに戻る</a>
      <a class="back" href="${escapeHtml(params.issuer)}/demo">デモ画面に戻る</a>
    </div>
  </main>
  <footer>ZK-App Portal (RP デモ) — PASTA + FROST + OAuth Proxy</footer>
  <script>${DPOP_SCRIPT}</script>
  <script>${TOKEN_SCRIPT}</script>
  <script>${TOKEN_PAGE_SCRIPT}</script>
</body>
</html>`;
}

export interface CallbackErrorParams {
  /** The RFC 6749 `error` code from the redirect. */
  error: string;
  /** The optional `error_description`. */
  errorDescription?: string;
  state?: string;
  issuer: string;
}

/**
 * The authorization server redirected back with an error instead of a code (RFC 6749
 * 4.1.2.1). No token flow to run, so this page carries no script at all.
 */
export function renderCallbackErrorPage(params: CallbackErrorParams): string {
  const rows = [
    `        <tr><th>error</th><td>${escapeHtml(params.error)}</td></tr>`,
    params.errorDescription
      ? `        <tr><th>error_description</th><td>${escapeHtml(params.errorDescription)}</td></tr>`
      : "",
    params.state ? `        <tr><th>state</th><td>${escapeHtml(params.state)}</td></tr>` : "",
  ]
    .filter(Boolean)
    .join("\n");

  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>ZK-App Portal - 認可失敗</title>
  <style>${SHARED_HEAD_STYLE}${CALLBACK_STYLE}
  </style>
</head>
<body>
  <header><span class="logo">ZK-App Portal</span></header>
  <main>
    <div class="card">
      <div class="banner ng">✖ 認可に失敗しました</div>
      <p class="detail">認可サーバーは認可コードではなくエラーを返しました。トークンの取得は行いません。</p>
      <table>
${rows}
      </table>
      <a class="back" href="/">← ZK-App Portal トップに戻る</a>
      <a class="back" href="${escapeHtml(params.issuer)}/demo">デモ画面に戻る</a>
    </div>
  </main>
  <footer>ZK-App Portal (RP デモ) — PASTA + FROST + OAuth Proxy</footer>
</body>
</html>`;
}

/** Plain error page for malformed requests. */
export function renderErrorPage(status: number, title: string, detail: string): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>ZK-App Portal - ${status}</title>
  <style>${SHARED_HEAD_STYLE}
    main { flex: 1; display: flex; align-items: center; justify-content: center; padding: 3rem 1rem; }
    .card { background: #fff; border: 1px solid #fecaca; border-radius: 12px; padding: 2rem; max-width: 600px; width: 100%; }
    h1 { font-size: 1.25rem; color: #b91c1c; margin: 0 0 0.75rem; }
    p { color: #475569; font-size: 0.875rem; line-height: 1.6; margin: 0; }
    a { display: inline-block; margin-top: 1.5rem; color: #6366f1; font-size: 0.875rem; text-decoration: none; }
  </style>
</head>
<body>
  <header><span class="logo">ZK-App Portal</span></header>
  <main>
    <div class="card">
      <h1>${status} ${escapeHtml(title)}</h1>
      <p>${escapeHtml(detail)}</p>
      <a href="/">← ZK-App Portal トップに戻る</a>
    </div>
  </main>
  <footer>ZK-App Portal (RP デモ) — PASTA + FROST + OAuth Proxy</footer>
</body>
</html>`;
}
