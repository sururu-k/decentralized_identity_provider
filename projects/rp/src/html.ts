import type { JwtPayload } from "./jwt.js";

/** Escapes text before interpolation so token contents can never inject markup. */
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

export interface LandingParams {
  authorizeUrl: string;
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
      <a class="login-btn" href="${escapeHtml(params.authorizeUrl)}">
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
}

export interface CallbackParams {
  valid: boolean;
  error?: string;
  payload: JwtPayload | null;
  /** IdP base URL, used for the "back to demo" link. */
  issuer: string;
  /** `state` echoed back by the IdP. Displayed only, never enforced. */
  state?: string;
}

function formatIat(payload: JwtPayload | null): string {
  const iat = payload?.iat;
  return typeof iat === "number" ? new Date(iat * 1000).toLocaleString("ja-JP") : "-";
}

/** The post-login page: verification outcome plus the decoded claim set. */
export function renderCallbackPage(params: CallbackParams): string {
  const { valid, payload, issuer } = params;
  const sub = payload?.sub ?? "(不明)";
  const iat = formatIat(payload);
  const nonce = payload?.nonce;
  const claimsJson = payload ? JSON.stringify(payload, null, 2) : "(トークンを解析できませんでした)";
  const avatarInitial = String(sub).slice(4, 5).toUpperCase() || "U";

  const banner = valid
    ? `      <div class="success-banner">
        <span class="check">&#10003;</span>
        <div>
          <strong>認証成功</strong><br>
          <span>PASTA 分散 IdP により Ed25519 署名が検証されました</span>
        </div>
      </div>`
    : `      <div class="failure-banner">
        <span class="cross">&#10007;</span>
        <div>
          <strong>認証失敗</strong><br>
          <span>ID トークンの検証に失敗しました: ${escapeHtml(params.error ?? "不明なエラー")}</span>
        </div>
      </div>`;

  // The demo UI always posts a `state` field, empty string included; an empty
  // value gets no row rather than a blank one.
  const optionalRows = [
    nonce ? `        <tr><th>nonce (表示のみ)</th><td>${escapeHtml(nonce)}</td></tr>` : "",
    params.state ? `        <tr><th>state (表示のみ)</th><td>${escapeHtml(params.state)}</td></tr>` : "",
  ]
    .filter(Boolean)
    .join("\n");

  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>ZK-App Portal - ${valid ? "ログイン成功" : "ログイン失敗"}</title>
  <style>${SHARED_HEAD_STYLE}
    .user-pill {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.875rem;
      color: #475569;
    }
    .avatar {
      width: 28px; height: 28px;
      background: ${valid ? "#4f46e5" : "#94a3b8"};
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
    .success-banner, .failure-banner {
      border-radius: 8px;
      padding: 0.875rem 1rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    .success-banner { background: #f0fdf4; border: 1px solid #bbf7d0; }
    .failure-banner { background: #fef2f2; border: 1px solid #fecaca; }
    .check { color: #16a34a; font-size: 1.25rem; }
    .cross { color: #dc2626; font-size: 1.25rem; }
    .success-banner strong { color: #15803d; }
    .success-banner span { font-size: 0.875rem; color: #166534; }
    .failure-banner strong { color: #b91c1c; }
    .failure-banner span { font-size: 0.875rem; color: #991b1b; }
    h2 { font-size: 1.25rem; color: #0f172a; margin: 0 0 1rem; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th, td { text-align: left; padding: 0.5rem 0.625rem; border-bottom: 1px solid #f1f5f9; }
    th { color: #64748b; font-weight: 500; width: 40%; }
    td { color: #1e293b; font-family: ui-monospace, monospace; font-size: 0.8125rem; word-break: break-all; }
    .detail { margin-top: 1.5rem; }
    summary { cursor: pointer; color: #6366f1; font-size: 0.875rem; font-weight: 500; padding: 0.5rem 0; }
    pre { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.875rem; font-size: 0.75rem; overflow-x: auto; color: #334155; margin: 0.5rem 0 0; }
    .back { display: inline-block; margin-top: 1.5rem; margin-right: 1.25rem; color: #6366f1; font-size: 0.875rem; font-weight: 500; text-decoration: none; }
    .back:hover { text-decoration: underline; }
    .note { font-size: 0.75rem; color: #94a3b8; margin-top: 1rem; line-height: 1.5; }
  </style>
</head>
<body>
  <header>
    <span class="logo">ZK-App Portal</span>
    <div class="user-pill">
      <div class="avatar">${escapeHtml(avatarInitial)}</div>
      <span>${escapeHtml(sub)}</span>
    </div>
  </header>
  <main>
    <div class="card">
${banner}
      <h2>ログイン情報</h2>
      <table>
        <tr><th>ユーザー識別子 (sub)</th><td>${escapeHtml(sub)}</td></tr>
        <tr><th>発行時刻 (iat)</th><td>${escapeHtml(iat)}</td></tr>
        <tr><th>署名検証</th><td>${valid ? "Ed25519 (EdDSA) — 有効" : "失敗: " + escapeHtml(params.error ?? "不明なエラー")}</td></tr>
        <tr><th>トークン配送経路</th><td>ブラウザ form_post (プロキシ非経由)</td></tr>
${optionalRows}
      </table>
      <details class="detail">
        <summary>JWT クレーム (生データ)</summary>
        <pre>${escapeHtml(claimsJson)}</pre>
      </details>
      <p class="note">
        OAuth プロキシは暗号化シェアを中継したのみで、このトークンの平文に関与していません。<br>
        RP はグループ公開鍵 (JWKS) を参照し、標準 Ed25519 として単独で検証しています。
      </p>
      <a class="back" href="/">← ZK-App Portal トップに戻る</a>
      <a class="back" href="${escapeHtml(issuer)}/demo">デモ画面に戻る</a>
    </div>
  </main>
  <footer>ZK-App Portal (RP デモ) — PASTA + FROST + OAuth Proxy</footer>
</body>
</html>`;
}

/** Plain error page for malformed requests and unreachable JWKS. */
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
