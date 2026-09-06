import { escapeHtml } from "./client-sdk/form-post.js";
import { VerifyJwtResult } from "./jwt/jwt.js";

/**
 * The page `POST /demo/rp-callback` renders.
 *
 * This is the demo UI's default `form_post` target: the stand-in relying party that the
 * browser posts its freshly minted `id_token` to when no real RP is in the flow
 * (`docs/container-split.md` section 6). The real relying party is the `rp` component.
 *
 * Everything interpolated below is attacker-supplied and arrives unauthenticated.
 * `state` is a plain form field, and a rejected token still yields an error message built
 * from its own unsigned header -- an `alg` of `<img src=x onerror=...>` lands in
 * "Unsupported alg: ...". The page is served from the gateway's own origin, alongside the
 * demo UI, so an unescaped value here is script running as the IdP. Every one of them is
 * escaped, which is why this file holds the markup instead of the router.
 */
export function renderDemoRpCallbackPage(
  verifyRes: VerifyJwtResult,
  state: string | undefined
): string {
  const status = verifyRes.valid
    ? '<span class="status-ok">✔ 有効な Ed25519 (EdDSA) IDトークンとして検証成功</span>'
    : `<span class="status-err">✖ 検証失敗: ${escapeHtml(String(verifyRes.error ?? ""))}</span>`;

  return `<!DOCTYPE html>
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
    <p>Ed25519 署名検証ステータス: ${status}</p>
    <h3>State パラメータ:</h3>
    <pre>${state ? escapeHtml(state) : "(指定なし)"}</pre>
    <h3>検証済み IDトークン ペイロード (Claims):</h3>
    <pre>${escapeHtml(JSON.stringify(verifyRes.payload, null, 2) ?? "(なし)")}</pre>
    <p style="margin-top: 1.5rem;"><a href="/demo" style="color: #6366f1; text-decoration: none; font-weight: 600;">← デモ画面に戻って別のサインオンを試す</a></p>
  </div>
</body>
</html>`;
}
