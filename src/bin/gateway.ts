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
