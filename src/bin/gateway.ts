import http from "node:http";
import url from "node:url";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generateShamirShares, randomScalar } from "../crypto/frost.js";
import { IdentityNode, registerUserToNodes } from "../protocol/node.js";
import { PastaOAuthProxy } from "../gateway/proxy.js";
import { OidcEndpointHandler } from "../gateway/oidc.js";
import { verifyJwt } from "../jwt/jwt.js";
import { DecentralizedClientSdk } from "../client-sdk/client.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEMO_DIST = path.resolve(__dirname, "../../demo/dist");

const PORT = parseInt(process.env.PORT || "3000", 10);
const ISSUER = process.env.ISSUER || `http://localhost:${PORT}`;

// 1. Initialize Distributed Nodes (3 nodes, threshold 2)
const secret = randomScalar();
const { groupPublicKey, shares } = generateShamirShares(secret, 2, 3);

const nodes: IdentityNode[] = [
  new IdentityNode(1, shares.get(1)!, groupPublicKey),
  new IdentityNode(2, shares.get(2)!, groupPublicKey),
  new IdentityNode(3, shares.get(3)!, groupPublicKey),
];

// Pre-register demo users on all nodes via client-side PASTA protocol
// Nodes receive only toprfKeyShare and h_i; nodes NEVER learn the passwords!
registerUserToNodes(nodes, "alice", "password123", "usr_alice_12345", 2);
registerUserToNodes(nodes, "bob", "password456", "usr_bob_67890", 2);

// 2. Initialize OAuth Proxy and OIDC Handler
const proxy = new PastaOAuthProxy(nodes, 2);
const oidc = new OidcEndpointHandler({
  issuer: ISSUER,
  groupPublicKey,
  keyId: "pasta-group-key-1",
});

function readJsonBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
        reject(new Error("Request body too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function readUrlEncodedBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
        reject(new Error("Request body too large"));
      }
    });
    req.on("end", () => {
      try {
        const parsed = new url.URLSearchParams(body);
        const result: Record<string, string> = {};
        for (const [key, value] of parsed.entries()) {
          result[key] = value;
        }
        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const pathname = reqUrl.pathname;
  const method = req.method || "GET";

  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, DPoP, Authorization");

  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // 1. OIDC Discovery Document
    if (method === "GET" && pathname === "/.well-known/openid-configuration") {
      const config = oidc.getDiscoveryConfiguration();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(config, null, 2));
      return;
    }

    // 2. OIDC JWKS Endpoint
    if (method === "GET" && pathname === "/jwks.json") {
      const jwks = oidc.getJwks();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(jwks, null, 2));
      return;
    }

    // 3. OIDC /authorize Endpoint
    if (method === "GET" && pathname === "/authorize") {
      const query: Record<string, string> = {};
      for (const [k, v] of reqUrl.searchParams.entries()) {
        query[k] = v;
      }
      const validation = oidc.validateAuthorizeRequest(query);
      if (!validation.valid || !validation.params) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end(`Authorize Error: ${validation.error}`);
        return;
      }

      const html = oidc.renderAuthorizePage(validation.params);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
      return;
    }

    // 4. Proxy Sign-On Endpoint (Hole 2: Proxy only relays blinded ciphertext shares)
    if (method === "POST" && pathname === "/api/pasta/sign-on") {
      const body = await readJsonBody(req);
      const result = await proxy.handleSignOn(body);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
      return;
    }

    // 5. Proxy Refresh Endpoint (Hole 5: Nodes verify DPoP proof independently)
    if (method === "POST" && pathname === "/api/pasta/refresh") {
      const body = await readJsonBody(req);
      const result = await proxy.handleRefresh(body);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
      return;
    }

    // 6. Browser sign-on helper for demo UI (executes Client SDK in-process to simulate browser aggregation)
    if (method === "POST" && pathname === "/api/pasta/browser-sign-on") {
      const body = await readJsonBody(req);
      const clientSdk = new DecentralizedClientSdk({ proxy, issuer: ISSUER });
      const { id_token, sessionId } = await clientSdk.signOn({
        username: body.username,
        password: body.password,
        clientId: body.clientId,
        nonce: body.nonce,
      });

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, id_token, sessionId }));
      return;
    }

    // 7. Demo Relying Party (RP) form_post Callback Endpoint
    if (method === "POST" && pathname === "/demo/rp-callback") {
      const formParams = await readUrlEncodedBody(req);
      const idToken = formParams.id_token;
      const stateParam = formParams.state;

      if (!idToken) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end("<h1>400 Bad Request: Missing id_token</h1>");
        return;
      }

      // RP independently verifies Ed25519 token using standard EdDSA verification
      const verifyRes = verifyJwt(idToken, groupPublicKey, {
        iss: ISSUER,
      });

      const resultHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>RP (連携サービス) - 認証成功</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b1120; color: #f1f5f9; padding: 2rem; }
    .card { background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 2rem; max-width: 680px; margin: 0 auto; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }
    pre { background: #0f172a; padding: 1rem; border-radius: 8px; overflow-x: auto; color: #38bdf8; font-size: 0.875rem; border: 1px solid #1e293b; }
    .status-ok { color: #34d399; font-weight: bold; }
    .status-err { color: #f87171; font-weight: bold; }
    .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; background: #312e81; color: #c7d2fe; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">連携先サービス: ZK-App Portal (RP)</span>
    <h2>RP コールバック受信成功</h2>
    <p>ブラウザから直接 <strong>response_mode=form_post</strong> によりクレデンシャルを受信しました。</p>
    <p style="font-size: 0.875rem; color: #94a3b8;">
      ※ OAuth プロキシは暗号化シェアを中継したのみで、トークンの平文に一切関与していません（ホワイトボード穴②解決）。
    </p>
    <p>Ed25519 署名検証ステータス: ${
      verifyRes.valid
        ? '<span class="status-ok">✔ 有効な Ed25519 (EdDSA) IDトークンとして検証成功</span>'
        : `<span class="status-err">✖ 検証失敗: ${verifyRes.error}</span>`
    }</p>
    <h3>State パラメータ:</h3>
    <pre>${stateParam || "(指定なし)"}</pre>
    <h3>検証済み IDトークン ペイロード (Claims):</h3>
    <pre>${JSON.stringify(verifyRes.payload, null, 2)}</pre>
    <p style="margin-top: 1.5rem;"><a href="/demo" style="color: #6366f1; text-decoration: none; font-weight: 600;">← デモ画面に戻って別のサインオンを試す</a></p>
  </div>
</body>
</html>`;

      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(resultHtml);
      return;
    }

    // 8. Serve React Web Demo UI
    if (method === "GET") {
      let filePath = "";
      if (pathname === "/" || pathname === "/demo") {
        filePath = path.join(DEMO_DIST, "index.html");
      } else if (pathname.startsWith("/assets/")) {
        filePath = path.join(DEMO_DIST, pathname);
      }

      if (filePath && fs.existsSync(filePath)) {
        const ext = path.extname(filePath);
        let contentType = "text/html; charset=utf-8";
        if (ext === ".js") contentType = "application/javascript";
        else if (ext === ".css") contentType = "text/css";
        else if (ext === ".svg") contentType = "image/svg+xml";

        const content = fs.readFileSync(filePath);
        res.writeHead(200, { "Content-Type": contentType });
        res.end(content);
        return;
      }
    }

    // 8b. RP Top Page: third-party service landing page with "Login with PASTA IdP" button
    if (method === "GET" && pathname === "/rp") {
      const authorizeUrl =
        `${ISSUER}/authorize?client_id=demo_client` +
        `&redirect_uri=http://localhost:${PORT}/rp/callback` +
        `&response_type=id_token&response_mode=form_post&scope=openid%20profile%20email` +
        `&nonce=${Math.random().toString(36).slice(2)}&state=rp-demo`;
      const rpTopHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>ZK-App Portal</title>
  <style>
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
    footer {
      text-align: center;
      padding: 1.5rem;
      font-size: 0.75rem;
      color: #94a3b8;
      border-top: 1px solid #e2e8f0;
    }
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
      <p>このサービスは PASTA 分散 IdP による OpenID Connect 認証に対応しています。<br>
         OAuth プロキシが平文トークンを保持せず、ブラウザが端末内で署名を集約します。</p>
      <a class="login-btn" href="${authorizeUrl}">
        <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0zM3 20a9 9 0 0 1 18 0"/>
        </svg>
        PASTA IdP でログイン
      </a>
    </div>
    <div class="features">
      <div class="feature"><strong>秘密分散鍵</strong>単一障害点なし</div>
      <div class="feature"><strong>ゼロ知識プロキシ</strong>AS はトークンを持たない</div>
      <div class="feature"><strong>標準 OIDC</strong>RP 側の改修不要</div>
    </div>
  </main>
  <footer>ZK-App Portal (RP デモ) — PASTA + FROST + OAuth Proxy</footer>
</body>
</html>`;
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(rpTopHtml);
      return;
    }

    // 8c. RP Callback: receives id_token via form_post, verifies, shows welcome screen
    if (method === "POST" && pathname === "/rp/callback") {
      const formParams = await readUrlEncodedBody(req);
      const idToken = formParams.id_token;

      if (!idToken) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end("<h1>400 Bad Request: Missing id_token</h1>");
        return;
      }

      const verifyRes = verifyJwt(idToken, groupPublicKey, { iss: ISSUER });
      const sub = verifyRes.payload?.sub ?? "(不明)";
      const iat = verifyRes.payload?.iat
        ? new Date((verifyRes.payload.iat as number) * 1000).toLocaleString("ja-JP")
        : "-";

      const rpCallbackHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>ZK-App Portal - ログイン成功</title>
  <style>
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
    .user-pill {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.875rem;
      color: #475569;
    }
    .avatar {
      width: 28px; height: 28px;
      background: #4f46e5;
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      color: #fff; font-size: 0.75rem; font-weight: 700;
    }
    main {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 3rem 1rem;
    }
    .card {
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 2rem;
      max-width: 600px;
      width: 100%;
      box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    .success-banner {
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 8px;
      padding: 0.875rem 1rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    .check { color: #16a34a; font-size: 1.25rem; }
    .success-banner strong { color: #15803d; }
    .success-banner span { font-size: 0.875rem; color: #166534; }
    h2 { font-size: 1.25rem; color: #0f172a; margin: 0 0 1rem; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th, td { text-align: left; padding: 0.5rem 0.625rem; border-bottom: 1px solid #f1f5f9; }
    th { color: #64748b; font-weight: 500; width: 40%; }
    td { color: #1e293b; font-family: ui-monospace, monospace; font-size: 0.8125rem; word-break: break-all; }
    .detail { margin-top: 1.5rem; }
    summary { cursor: pointer; color: #6366f1; font-size: 0.875rem; font-weight: 500; padding: 0.5rem 0; }
    pre { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.875rem; font-size: 0.75rem; overflow-x: auto; color: #334155; margin: 0.5rem 0 0; }
    .back { display: inline-block; margin-top: 1.5rem; color: #6366f1; font-size: 0.875rem; font-weight: 500; text-decoration: none; }
    .back:hover { text-decoration: underline; }
    .note { font-size: 0.75rem; color: #94a3b8; margin-top: 1rem; line-height: 1.5; }
    footer {
      text-align: center;
      padding: 1.5rem;
      font-size: 0.75rem;
      color: #94a3b8;
      border-top: 1px solid #e2e8f0;
    }
  </style>
</head>
<body>
  <header>
    <span class="logo">ZK-App Portal</span>
    <div class="user-pill">
      <div class="avatar">${String(sub).slice(4, 5).toUpperCase() || "U"}</div>
      <span>${sub}</span>
    </div>
  </header>
  <main>
    <div class="card">
      <div class="success-banner">
        <span class="check">&#10003;</span>
        <div>
          <strong>認証成功</strong><br>
          <span>PASTA 分散 IdP により Ed25519 署名が検証されました</span>
        </div>
      </div>
      <h2>ログイン情報</h2>
      <table>
        <tr><th>ユーザー識別子 (sub)</th><td>${sub}</td></tr>
        <tr><th>発行時刻 (iat)</th><td>${iat}</td></tr>
        <tr><th>署名検証</th><td>${verifyRes.valid ? "Ed25519 (EdDSA) — 有効" : "失敗: " + verifyRes.error}</td></tr>
        <tr><th>トークン配送経路</th><td>ブラウザ form_post (プロキシ非経由)</td></tr>
      </table>
      <details class="detail">
        <summary>JWT クレーム (生データ)</summary>
        <pre>${JSON.stringify(verifyRes.payload, null, 2)}</pre>
      </details>
      <p class="note">
        OAuth プロキシは暗号化シェアを中継したのみで、このトークンの平文に関与していません。<br>
        RP はグループ公開鍵 (JWKS) を参照し、標準 Ed25519 として単独で検証しています。
      </p>
      <a class="back" href="/rp">← ZK-App Portal トップに戻る</a>
    </div>
  </main>
  <footer>ZK-App Portal (RP デモ) — PASTA + FROST + OAuth Proxy</footer>
</body>
</html>`;
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(rpCallbackHtml);
      return;
    }

    // Default 404
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  } catch (err: any) {
    console.error("Gateway Server Error:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: err.message || "Internal server error" }));
  }
});

server.listen(PORT, () => {
  console.log(`[Gateway] OAuth Proxy & OIDC Gateway listening at ${ISSUER}`);
  console.log(`[Gateway] Discovery: ${ISSUER}/.well-known/openid-configuration`);
  console.log(`[Gateway] JWKS:      ${ISSUER}/jwks.json`);
  console.log(
    `[Gateway] Authorize: ${ISSUER}/authorize?client_id=demo_client&redirect_uri=http://localhost:${PORT}/demo/rp-callback&response_type=id_token&response_mode=form_post&scope=openid&nonce=random_nonce`
  );
});

export { server, proxy, oidc, groupPublicKey };
