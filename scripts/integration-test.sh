#!/usr/bin/env bash
#
# 総合テスト: docker-compose.yml で 4 コンポーネントを起動し、契約
# (docs/container-split.md 第 14 節 OAuth 認可コードフロー) の成立する性質を上から順に確認する。
#
#   scripts/integration-test.sh
#   KEEP_UP=1 scripts/integration-test.sh   # 終了時に compose を落とさない
#
# 「ブラウザ役」は CLI スタンドイン (第 11・13・14 節、projects/demo/cli/sign-on.ts)。
# rp フロントと IdP フロントの両方を演じ、authorize→sign-on→code(アサーション)→/token を
# 一気通貫して **access_token を stdout 最終行** に出す。ブラウザで動くのと同じ SDK を Node で
# 実行するので **Node.js 20 以上が必要**。projects/demo/node_modules が無ければこのスクリプトが npm ci する。
#
# 終了時 (成功・失敗・中断いずれも) に `docker compose down` する。`--volumes` は
# 付けないので、ホストの secrets/ は残る = 次回起動でも鍵は同じ。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATEWAY="http://localhost:3000"
ISSUER="http://localhost:3000"
RP="http://localhost:3001"
CLIENT_ID="demo_client"
EXPECTED_SUB="usr_alice_12345"
EXPECTED_KID="pasta-group-key-1"
ALL_SERVICES="dealer node1 node2 node3 gateway rp"

PASSED=0
FAILED=0
WORK="$(mktemp -d)"

if [ -t 1 ]; then
  C_PASS=$'\033[32m'; C_FAIL=$'\033[31m'; C_STEP=$'\033[1;36m'; C_OFF=$'\033[0m'
else
  C_PASS=''; C_FAIL=''; C_STEP=''; C_OFF=''
fi

cleanup() {
  local rc=$?
  rm -rf "$WORK"
  if [ "${KEEP_UP:-0}" = "1" ]; then
    echo
    echo "KEEP_UP=1 のためスタックは起動したままです (docker compose down で停止)。"
  else
    echo
    echo "--- docker compose down ---"
    docker compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  exit $rc
}
trap cleanup EXIT

step() { echo; echo "${C_STEP}== $* ==${C_OFF}"; }
pass() { PASSED=$((PASSED + 1)); echo "  ${C_PASS}[PASS]${C_OFF} $1"; }
fail() { FAILED=$((FAILED + 1)); echo "  ${C_FAIL}[FAIL]${C_OFF} $1"; }

# ok <desc> <exit-status>
ok() { if [ "$2" -eq 0 ]; then pass "$1"; else fail "$1"; fi; }

# eq <desc> <expected> <actual>
eq() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected='$2' actual='$3')"; fi
}

# has <desc> <needle> <haystack>
has() {
  case "$3" in
    *"$2"*) pass "$1" ;;
    *) fail "$1 (not found: '$2')" ;;
  esac
}

# hasnt <desc> <needle> <haystack>
hasnt() {
  case "$3" in
    *"$2"*) fail "$1 (found: '$2')" ;;
    *) pass "$1" ;;
  esac
}

# http <method> <url> [curl args...] -> HTTP_CODE / HTTP_BODY
HTTP_CODE=""; HTTP_BODY=""
http() {
  local method="$1" url="$2"; shift 2
  local body_file="$WORK/body"
  HTTP_CODE="$(curl -s -o "$body_file" -w '%{http_code}' -X "$method" "$@" "$url" || echo 000)"
  HTTP_BODY="$(cat "$body_file")"
}

# jsonget <json> <expr>  — 例: jsonget "$body" 'd.issuer'
jsonget() {
  printf '%s' "$1" | node -e '
    let s = "";
    process.stdin.on("data", (c) => (s += c)).on("end", () => {
      let d;
      try { d = JSON.parse(s); } catch { process.stdout.write("<unparseable>"); return; }
      let v;
      try { v = eval(process.argv[1]); } catch { v = undefined; }
      process.stdout.write(v === undefined || v === null ? "" : String(v));
    });
  ' "$2"
}

# ブラウザ役 CLI スタンドイン (契約 第 11・13・14 節)。
#   sign_on <user> <password> <nonce> [--refresh ...]
# authorize→sign-on→code(アサーション)→/token を通し access_token を返す。
# 結果は SIGN_ON_TOKEN (access_token) / SIGN_ON_STATUS / SIGN_ON_STDERR に入る。
# サブシェルで呼ぶと結果が伝わらないので `$(sign_on ...)` の形では使わないこと。
SIGN_ON_TOKEN=""; SIGN_ON_STATUS=0; SIGN_ON_STDERR=""
sign_on() {
  local user="$1" password="$2" nonce="$3"
  shift 3
  local out
  set +e
  out="$(
    cd "$ROOT/projects/demo" &&
      npm run -s sign-on -- \
        --gateway "$GATEWAY" --user "$user" --password "$password" \
        --client-id "$CLIENT_ID" --nonce "$nonce" "$@" 2>"$WORK/cli.err" |
      tail -1
  )"
  SIGN_ON_STATUS=$?
  set -e
  SIGN_ON_TOKEN="$out"
  SIGN_ON_STDERR="$(cat "$WORK/cli.err" 2>/dev/null || true)"
}

# 認証アサーション (認可コード) だけを取り出す (--jkt: 秘密鍵は手元に無い想定)。
# ASSERTION に入れる。
mint_assertion() {
  local user="$1" password="$2" nonce="$3" jkt="$4"
  ASSERTION="$(
    cd "$ROOT/projects/demo" &&
      npm run -s sign-on -- \
        --gateway "$GATEWAY" --user "$user" --password "$password" \
        --client-id "$CLIENT_ID" --nonce "$nonce" --jkt "$jkt" 2>/dev/null |
      tail -1
  )"
}

# ANSI 色 (イメージは FORCE_COLOR=1 が既定) を落としてから grep する。
strip_ansi() { sed -e $'s/\033\\[[0-9;]*[a-zA-Z]//g'; }
logs_of() { docker compose logs --no-log-prefix "$1" 2>/dev/null | strip_ansi; }

# count_all <needle> — 全サービスのログに現れた行数の合計
count_all() {
  local needle="$1" total=0 svc n
  for svc in $ALL_SERVICES; do
    n="$(logs_of "$svc" | grep -c -- "$needle" || true)"
    total=$((total + n))
  done
  echo "$total"
}

# ノードが healthy になるまで待つ (docker compose start は待ってくれない)
wait_healthy() {
  local deadline=$((SECONDS + 90))
  while [ $SECONDS -lt $deadline ]; do
    local unhealthy=0
    for svc in "$@"; do
      local cid state
      cid="$(docker compose ps -q "$svc" 2>/dev/null || true)"
      if [ -z "$cid" ]; then unhealthy=1; break; fi
      state="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo none)"
      [ "$state" = "healthy" ] || unhealthy=1
    done
    [ "$unhealthy" -eq 0 ] && return 0
    sleep 1
  done
  return 1
}

echo "PASTA 分散 IdP — docker compose 総合テスト (OAuth 認可コードフロー, 契約 第 14 節)"
echo "リポジトリ: $ROOT"

# ---------------------------------------------------------------------------
step "0. 前提チェック (Node.js 20 以上 / npm / ブラウザ役 CLI の依存)"
if ! command -v node >/dev/null 2>&1; then
  echo "  node が見つかりません。ブラウザ役 CLI (projects/demo/cli/sign-on.ts) に Node.js 20 以上が必要です。"
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "  npm が見つかりません。projects/demo の依存解決に必要です。"
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "  Node.js $(node -v) は古すぎます。ブラウザ役 CLI には 20 以上が必要です"
  echo "  (globalThis.crypto が WebCrypto であること、fetch 組み込みが前提)。"
  exit 1
fi
pass "Node.js $(node -v) (20 以上) と npm $(npm -v) がある"

if [ -d projects/demo/node_modules ]; then
  pass "projects/demo/node_modules がある"
else
  echo "  projects/demo/node_modules が無いので npm ci します (初回のみ、1 分ほどかかります)…"
  if npm ci --prefix projects/demo >"$WORK/npm-ci.log" 2>&1; then
    pass "npm ci --prefix projects/demo が成功した"
  else
    fail "npm ci --prefix projects/demo が失敗した"
    tail -20 "$WORK/npm-ci.log"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
step "1. スタック起動 (docker compose up -d --build --wait)"
mkdir -p secrets
UP_START=$SECONDS
if docker compose up -d --build --wait; then
  UP_SECONDS=$((SECONDS - UP_START))
  pass "全サービスが healthy になった (${UP_SECONDS} 秒)"
else
  UP_SECONDS=$((SECONDS - UP_START))
  fail "docker compose up が失敗した (${UP_SECONDS} 秒)"
  docker compose ps
  echo; echo "起動に失敗したため以降のステップは実行できません。"
  echo "結果: ${PASSED} passed, ${FAILED} failed"
  exit 1
fi

for f in group.json node-1.json node-2.json node-3.json; do
  ok "secrets/$f が生成された" "$([ -s "secrets/$f" ] && echo 0 || echo 1)"
done

# ---------------------------------------------------------------------------
step "2. OAuth / OIDC Discovery (契約 第 14.4 節: response_types=[code], DPoP)"
http GET "$GATEWAY/.well-known/openid-configuration"
eq "GET /.well-known/openid-configuration が 200" 200 "$HTTP_CODE"
eq "issuer が $ISSUER" "$ISSUER" "$(jsonget "$HTTP_BODY" 'd.issuer')"
eq "token_endpoint が $ISSUER/token" "$ISSUER/token" "$(jsonget "$HTTP_BODY" 'd.token_endpoint')"
JWKS_URI="$(jsonget "$HTTP_BODY" 'd.jwks_uri')"
eq "jwks_uri が $ISSUER/jwks.json" "$ISSUER/jwks.json" "$JWKS_URI"
eq "response_types_supported が [code]" "code" \
  "$(jsonget "$HTTP_BODY" 'd.response_types_supported.join(",")')"
GRANTS="$(jsonget "$HTTP_BODY" 'd.grant_types_supported.join(",")')"
has "grant_types_supported に authorization_code" "authorization_code" "$GRANTS"
has "grant_types_supported に refresh_token" "refresh_token" "$GRANTS"
eq "dpop_signing_alg_values_supported が [EdDSA]" "EdDSA" \
  "$(jsonget "$HTTP_BODY" 'd.dpop_signing_alg_values_supported.join(",")')"

# ---------------------------------------------------------------------------
step "3. JWKS (グループ公開鍵)"
http GET "$JWKS_URI"
eq "GET /jwks.json が 200" 200 "$HTTP_CODE"
JWKS_BODY="$HTTP_BODY"
printf '%s' "$JWKS_BODY" > "$WORK/jwks.json"
eq "kid が $EXPECTED_KID" "$EXPECTED_KID" "$(jsonget "$JWKS_BODY" 'd.keys[0].kid')"
eq "kty が OKP" "OKP" "$(jsonget "$JWKS_BODY" 'd.keys[0].kty')"
eq "crv が Ed25519" "Ed25519" "$(jsonget "$JWKS_BODY" 'd.keys[0].crv')"
eq "alg が EdDSA" "EdDSA" "$(jsonget "$JWKS_BODY" 'd.keys[0].alg')"
JWKS_X_FIRST="$(jsonget "$JWKS_BODY" 'd.keys[0].x')"
ok "公開鍵 x が base64url 43 文字 (Ed25519 32 バイト)" \
  "$([ "${#JWKS_X_FIRST}" -eq 43 ] && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
step "4. ヘルスチェック"
http GET "$GATEWAY/health"
eq "gateway /health が 200" 200 "$HTTP_CODE"
eq "gateway /health の status が ok" "ok" "$(jsonget "$HTTP_BODY" 'd.status')"
eq "gateway が healthy なノードを 3 件見ている" "3" \
  "$(jsonget "$HTTP_BODY" 'd.nodes.filter((n) => n.healthy).length')"
eq "gateway が見ている nodeId が 1,2,3" "1,2,3" \
  "$(jsonget "$HTTP_BODY" 'd.nodes.map((n) => n.nodeId).sort().join(",")')"

http GET "$RP/health"
eq "rp /health が 200" 200 "$HTTP_CODE"
eq "rp /health の status が ok" "ok" "$(jsonget "$HTTP_BODY" 'd.status')"

for n in 1 2 3; do
  http GET "http://localhost:400$n/health"
  eq "node$n /health が 200" 200 "$HTTP_CODE"
  eq "node$n の nodeId が $n" "$n" "$(jsonget "$HTTP_BODY" 'd.nodeId')"
done

# ---------------------------------------------------------------------------
step "5. authorization_code grant — CLI で access_token を取得"
NONCE="itest-$(node -e 'process.stdout.write(require("node:crypto").randomBytes(12).toString("hex"))')"
sign_on alice password123 "$NONCE"
ok "npm run sign-on が exit 0" "$SIGN_ON_STATUS"
ACCESS_TOKEN="$SIGN_ON_TOKEN"
ok "stdout の最終行に access_token が出た" "$([ -n "$ACCESS_TOKEN" ] && echo 0 || echo 1)"
eq "access_token が 3 セグメントの JWS" "3" \
  "$(printf '%s' "$ACCESS_TOKEN" | awk -F. '{print NF}')"
has "stderr にブラウザ列のデモログが出ている" "[browser] sign-on   user=alice" "$SIGN_ON_STDERR"
has "ブラウザ列にアサーション (=認可コード) 生成の印がある" \
  "assertion" "$SIGN_ON_STDERR"
has "ブラウザ列に /token grant=authorization_code のイベントがある" \
  "grant=authorization_code" "$SIGN_ON_STDERR"
hasnt "CLI の出力にパスワードが出ていない" "password123" "$SIGN_ON_STDERR$ACCESS_TOKEN"
printf '%s' "$ACCESS_TOKEN" > "$WORK/token.txt"

# ---------------------------------------------------------------------------
step "6. 外部検証器 (node:crypto、IdP コード不使用) で access_token を検証"
cat > "$WORK/verify.mjs" <<'VERIFY_EOF'
// IdP の実装を一切読み込まない独立検証器。node:crypto の Ed25519 だけで JWS を検証する。
import { readFileSync } from "node:fs";
import { verify } from "node:crypto";

const [tokenPath, jwksPath, wantIss, wantAud, wantSub] = process.argv.slice(2);
const token = readFileSync(tokenPath, "utf8").trim();
const jwks = JSON.parse(readFileSync(jwksPath, "utf8"));

const results = [];
const record = (name, value) => results.push(`${name}=${value ? "true" : "false"}`);

const b64uToBuf = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const bufToB64u = (b) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const [h, p, s] = token.split(".");
const header = JSON.parse(b64uToBuf(h).toString("utf8"));

let payload = null;
let payloadParsed = true;
try {
  payload = JSON.parse(b64uToBuf(p).toString("utf8"));
} catch {
  payloadParsed = false;
}
record("payload_json", payloadParsed);

record("alg_eddsa", header.alg === "EdDSA");
record("typ_at_jwt", header.typ === "at+jwt");
const jwk = jwks.keys.find((k) => k.kid === header.kid);
record("kid_in_jwks", Boolean(jwk));

const verifyWith = (signingInput, sig) =>
  verify(null, Buffer.from(signingInput, "utf8"), { key: jwk, format: "jwk" }, sig);

record("signature", Boolean(jwk) && verifyWith(`${h}.${p}`, b64uToBuf(s)));

record("iss", payload?.iss === wantIss);
record("aud", payload?.aud === wantAud);
record("sub", payload?.sub === wantSub);
record("exp_future", typeof payload?.exp === "number" && payload.exp > Math.floor(Date.now() / 1000));
record("exp_gt_iat", typeof payload?.exp === "number" && typeof payload?.iat === "number" && payload.exp > payload.iat);
record("cnf_jkt", typeof payload?.cnf?.jkt === "string" && payload.cnf.jkt.length > 0);

// sub を改竄したトークンは検証に失敗しなければならない (署名はそのまま)。
const tampered = { ...payload, sub: "usr_mallory_00000" };
const tamperedP = bufToB64u(Buffer.from(JSON.stringify(tampered), "utf8"));
record("tampered_rejected", Boolean(jwk) && !verifyWith(`${h}.${tamperedP}`, b64uToBuf(s)));

process.stdout.write(results.join("\n"));
VERIFY_EOF

VERIFY_OUT="$(node "$WORK/verify.mjs" "$WORK/token.txt" "$WORK/jwks.json" \
  "$ISSUER" "$CLIENT_ID" "$EXPECTED_SUB")"

verified() { printf '%s\n' "$VERIFY_OUT" | grep -qx "$1=true" && echo 0 || echo 1; }
ok "ペイロードが JSON.parse できる"                     "$(verified payload_json)"
ok "ヘッダの alg が EdDSA"                              "$(verified alg_eddsa)"
ok "ヘッダの typ が at+jwt (アクセストークン)"          "$(verified typ_at_jwt)"
ok "ヘッダの kid が JWKS に存在する"                    "$(verified kid_in_jwks)"
ok "Ed25519 署名が JWKS の鍵で検証できる"               "$(verified signature)"
ok "iss が $ISSUER"                                     "$(verified iss)"
ok "aud が $CLIENT_ID"                                  "$(verified aud)"
ok "sub が $EXPECTED_SUB"                               "$(verified sub)"
ok "exp が未来"                                         "$(verified exp_future)"
ok "exp > iat"                                          "$(verified exp_gt_iat)"
ok "cnf.jkt (DPoP 束縛) がある"                         "$(verified cnf_jkt)"
ok "sub を改竄すると署名検証が落ちる"                   "$(verified tampered_rejected)"

# ---------------------------------------------------------------------------
step "7. refresh_token grant — 新 access_token も JWKS で検証できる"
REFRESH_NONCE="itest-refresh-$$"
sign_on alice password123 "$REFRESH_NONCE" --refresh
ok "npm run sign-on -- --refresh が exit 0" "$SIGN_ON_STATUS"
REFRESHED_TOKEN="$SIGN_ON_TOKEN"
ok "リフレッシュ後の access_token が返った" "$([ -n "$REFRESHED_TOKEN" ] && echo 0 || echo 1)"
ok "リフレッシュ前後でトークンが違う" \
  "$([ "$REFRESHED_TOKEN" != "$ACCESS_TOKEN" ] && echo 0 || echo 1)"
has "ブラウザ列に refresh grant のイベントが出ている" "grant=refresh_token" "$SIGN_ON_STDERR"

printf '%s' "$REFRESHED_TOKEN" > "$WORK/refreshed.txt"
VERIFY_OUT="$(node "$WORK/verify.mjs" "$WORK/refreshed.txt" "$WORK/jwks.json" \
  "$ISSUER" "$CLIENT_ID" "$EXPECTED_SUB")"
ok "リフレッシュ後の typ が at+jwt"                       "$(verified typ_at_jwt)"
ok "リフレッシュ後の Ed25519 署名が JWKS の鍵で検証できる" "$(verified signature)"
ok "リフレッシュ後も sub が $EXPECTED_SUB"                "$(verified sub)"
ok "リフレッシュ後も aud が $CLIENT_ID"                   "$(verified aud)"
ok "リフレッシュ後も cnf.jkt がある"                      "$(verified cnf_jkt)"
ok "リフレッシュ後の exp が未来"                          "$(verified exp_future)"

# ---------------------------------------------------------------------------
step "8. DPoP 束縛の確認 (契約 第 14 節の肝) — proof 無しでは発行されない"
# (a) proof 無しで /token を叩くと 400 (invalid_dpop_proof)。
http POST "$GATEWAY/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'grant_type=authorization_code&code=x&client_id=demo_client'
eq "proof 無しの /token は 400" 400 "$HTTP_CODE"
has "エラーが invalid_dpop_proof" "invalid_dpop_proof" "$HTTP_BODY"

# (b) 別の鍵の proof + 正当な code は 400 (proof の jkt ≠ アサーションの cnf.jkt)。
EXT_JKT="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64url"))')"
mint_assertion alice password123 "itest-dpop-$$" "$EXT_JKT"
ok "外部 jkt に束縛したアサーション (code) を取得できた" \
  "$([ "$(printf '%s' "$ASSERTION" | awk -F. '{print NF}')" -eq 3 ] && echo 0 || echo 1)"
WRONG_PROOF="$(node -e '
  const c = require("node:crypto");
  const { publicKey, privateKey } = c.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  const b64u = (b) => Buffer.from(b).toString("base64url");
  const h = { typ: "dpop+jwt", alg: "EdDSA", jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x } };
  const p = { jti: c.randomBytes(16).toString("base64url"), htm: "POST",
    htu: "'"$ISSUER"'/token", iat: Math.floor(Date.now() / 1000) };
  const si = b64u(JSON.stringify(h)) + "." + b64u(JSON.stringify(p));
  const sig = c.sign(null, Buffer.from(si), privateKey);
  process.stdout.write(si + "." + b64u(sig));
')"
http POST "$GATEWAY/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "DPoP: $WRONG_PROOF" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$ASSERTION" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$RP/callback"
eq "別の鍵の proof + 正当な code は 400" 400 "$HTTP_CODE"
has "エラーが invalid_dpop_proof (jkt 不一致)" "invalid_dpop_proof" "$HTTP_BODY"

# (c) gateway の OPTIONS /token が CORS プリフライトで DPoP を許可する (契約 第 14.4 節)。
http OPTIONS "$GATEWAY/token" \
  -D "$WORK/cors.hdr" \
  -H 'Origin: http://localhost:3001' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: DPoP'
CORS_ALLOW_HEADERS="$(grep -i '^access-control-allow-headers:' "$WORK/cors.hdr" || true)"
has "OPTIONS /token の Allow-Headers に DPoP がある" "DPoP" "$CORS_ALLOW_HEADERS"
CORS_ALLOW_METHODS="$(grep -i '^access-control-allow-methods:' "$WORK/cors.hdr" || true)"
has "OPTIONS /token の Allow-Methods に POST がある" "POST" "$CORS_ALLOW_METHODS"

# ---------------------------------------------------------------------------
step "9. 誤ったパスワード — アサーションが作れず認可コードに至らない"
sign_on alice wrong "itest-bad-$$"
ok "誤パスワードで CLI が exit 1" "$([ "$SIGN_ON_STATUS" -ne 0 ] && echo 0 || echo 1)"
ok "access_token が出ていない" "$([ -z "$SIGN_ON_TOKEN" ] && echo 0 || echo 1)"
has "ブラウザ列に復号失敗の印がある" "ct_1 decrypt failed" "$SIGN_ON_STDERR"
has "「ノードは成否を知らない」が出ている" "nodes cannot tell" "$SIGN_ON_STDERR"

http GET "$GATEWAY/health"
eq "誤パスワードでも gateway は正常なまま (ノード側はエラーにならない)" 200 "$HTTP_CODE"

# ---------------------------------------------------------------------------
step "10. rp ランディング / コールバック (契約 第 7・14 節: HTML 配信のみ)"
http GET "$RP/"
eq "GET / が 200" 200 "$HTTP_CODE"
has "authorize URL が response_type=code" "response_type=code" "$HTTP_BODY"
has "redirect_uri が rp 自身の /callback" \
  "redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback" "$HTTP_BODY"
has "認可エンドポイントが gateway" "http://localhost:3000/authorize" "$HTTP_BODY"
has "WebCrypto で Ed25519 の DPoP 鍵を作るインライン JS がある" \
  'generateKey({ name: "Ed25519" }' "$HTTP_BODY"
has "秘密鍵の保管先が IndexedDB の pasta-rp" 'var DB_NAME = "pasta-rp"' "$HTTP_BODY"
has "authorize URL に dpop_jkt を組み立てる JS がある" \
  '"&dpop_jkt=" + encodeURIComponent(jkt)' "$HTTP_BODY"
has "jkt 確定前はログインリンクが無効" 'aria-disabled="true"' "$HTTP_BODY"

http GET "$RP/callback?code=aaa.bbb.ccc&state=itest-cb-$$"
eq "GET /callback?code&state が 200" 200 "$HTTP_CODE"
has "code が data-code に埋まっている" "data-code=" "$HTTP_BODY"

http GET "$RP/callback?error=access_denied&state=itest-cb-$$"
eq "GET /callback?error=... が 400" 400 "$HTTP_CODE"

http GET "$RP/callback"
eq "GET /callback (code も error も無し) が 400" 400 "$HTTP_CODE"

# ---------------------------------------------------------------------------
step "11. デモログ (契約 第 10 節) — 各列が何を知っているか"
LOG_NONCE="itlog-$$-${RANDOM}"
sign_on alice password123 "$LOG_NONCE"
ok "デモログ検証用のサインオンが成功した" "$SIGN_ON_STATUS"

# (a) gateway に今回の nonce の sign-on 行と、token 行 (grant=authz + access_token)。
GW_SIGNON="$(logs_of gateway | grep -- "nonce=$LOG_NONCE" | grep -- "sign-on" | tail -1)"
has "gateway に今回の sign-on 行が出ている" "[gateway] sign-on" "$GW_SIGNON"
has "その行に user=alice がある" "user=alice" "$GW_SIGNON"
has "その行にパスワードを受け取っていない印 (no pw) がある" "(no pw)" "$GW_SIGNON"
GW_TOKEN="$(logs_of gateway | grep -E 'token .*grant=authz' | tail -1)"
has "gateway に token grant=authz の行が出ている" "grant=authz" "$GW_TOKEN"
has "その token 行に合成した access_token が出ている" "access_token " "$GW_TOKEN"

# (b) node1..3 に sign (grant=authz) 行と、起動行の never 宣言。
for n in 1 2 3; do
  NODE_SIGN="$(logs_of "node$n" | grep -E 'sign +round=.*grant=authz' | tail -1)"
  has "node$n に sign (grant=authz) 行が出ている" "grant=authz" "$NODE_SIGN"
  has "node$n の sign 行にアサーション署名の検証印がある" "assertion" "$NODE_SIGN"
  has "node$n が起動行で never を宣言している" \
    "never: pw, h, other s_i/k_i" "$(logs_of "node$n")"
done

# (c) パスワードがどのログにも出ていない。
eq "全サービスのログに password123 が 0 件" "0" "$(count_all 'password123')"

# (d) 長期秘密 (secretKeyShare) の先頭 16 文字がどのログにも出ていない。
SK_PREFIX="$(node -e '
  const fs = require("node:fs");
  const j = JSON.parse(fs.readFileSync("secrets/node-1.json", "utf8"));
  process.stdout.write(String(j.secretKeyShare).slice(0, 16));
')"
ok "secrets/node-1.json から secretKeyShare を読めた" \
  "$([ "${#SK_PREFIX}" -eq 16 ] && echo 0 || echo 1)"
eq "全サービスのログに secretKeyShare の先頭 16 文字が 0 件" "0" "$(count_all "$SK_PREFIX")"

# ---------------------------------------------------------------------------
step "12. node3 停止 — 2-of-3 で継続できる"
docker compose stop node3 >/dev/null 2>&1
EXCLUDE_NONCE="itest-2of3-$$"
sign_on alice password123 "$EXCLUDE_NONCE"
ok "node3 停止後もサインオンが成功する" "$SIGN_ON_STATUS"
ok "access_token が返る" "$([ -n "$SIGN_ON_TOKEN" ] && echo 0 || echo 1)"

printf '%s' "$SIGN_ON_TOKEN" > "$WORK/token-2of3.txt"
VERIFY_OUT="$(node "$WORK/verify.mjs" "$WORK/token-2of3.txt" "$WORK/jwks.json" \
  "$ISSUER" "$CLIENT_ID" "$EXPECTED_SUB")"
ok "2-of-3 の access_token も JWKS で検証できる" "$(verified signature)"

# nonce は sign-on の 1 行目にしか無い。除外の内訳は 2 行目 (round1) なので -A1 で拾う。
GW_EXCLUDE="$(logs_of gateway | grep -A1 -- "nonce=$EXCLUDE_NONCE" || true)"
has "gateway の round1 行に「除外」が出る" "unreachable, excluded" "$GW_EXCLUDE"
has "除外されたのが node3" "node3 unreachable, excluded" "$GW_EXCLUDE"

http GET "$GATEWAY/health"
eq "gateway /health は 200 のまま (閾値を満たす)" 200 "$HTTP_CODE"
eq "status が ok" "ok" "$(jsonget "$HTTP_BODY" 'd.status')"
eq "node3 が unhealthy として報告される" "false" \
  "$(jsonget "$HTTP_BODY" 'd.nodes.find((n) => n.nodeId === 3).healthy')"
eq "healthy なノードは 2 件" "2" \
  "$(jsonget "$HTTP_BODY" 'd.nodes.filter((n) => n.healthy).length')"

# ---------------------------------------------------------------------------
step "13. node2 も停止 — 閾値を割って失敗する"
docker compose stop node2 >/dev/null 2>&1
sign_on alice password123 "itest-1of3-$$"
ok "node2,3 停止でサインオンが失敗する (exit 1)" \
  "$([ "$SIGN_ON_STATUS" -ne 0 ] && echo 0 || echo 1)"
ok "access_token は出ない" "$([ -z "$SIGN_ON_TOKEN" ] && echo 0 || echo 1)"

http GET "$GATEWAY/health"
eq "gateway /health が 503" 503 "$HTTP_CODE"
eq "status が degraded" "degraded" "$(jsonget "$HTTP_BODY" 'd.status')"

# ---------------------------------------------------------------------------
step "14. node2, node3 を復旧 — gateway 再起動なしで戻る"
docker compose start node2 node3 >/dev/null 2>&1
if wait_healthy node2 node3; then
  pass "node2, node3 が healthy に復帰した"
else
  fail "node2, node3 が 90 秒以内に healthy にならなかった"
fi

http GET "$GATEWAY/health"
eq "gateway /health が 200 に戻る" 200 "$HTTP_CODE"
eq "healthy なノードが 3 件に戻る" "3" \
  "$(jsonget "$HTTP_BODY" 'd.nodes.filter((n) => n.healthy).length')"

sign_on alice password123 "itest-recovered-$$"
ok "gateway を再起動せずにサインオンが成功する" "$SIGN_ON_STATUS"
ok "access_token が返る" "$([ -n "$SIGN_ON_TOKEN" ] && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
step "15. dealer の冪等性 (--if-missing で鍵が変わらない)"
GROUP_BEFORE="$(cat secrets/group.json)"
NODE1_BEFORE="$(cat secrets/node-1.json)"
if docker compose run --rm dealer --out /secrets --if-missing >"$WORK/dealer.log" 2>&1; then
  pass "docker compose run dealer --if-missing が exit 0"
else
  fail "docker compose run dealer --if-missing が非 0 で終了した"
  cat "$WORK/dealer.log"
fi
eq "secrets/group.json が変わっていない" "$GROUP_BEFORE" "$(cat secrets/group.json)"
eq "secrets/node-1.json が変わっていない" "$NODE1_BEFORE" "$(cat secrets/node-1.json)"

# ---------------------------------------------------------------------------
step "16. 停止 → 再起動で鍵が保持される"
docker compose down --remove-orphans >/dev/null 2>&1
RESTART_START=$SECONDS
if docker compose up -d --wait >/dev/null 2>&1; then
  RESTART_SECONDS=$((SECONDS - RESTART_START))
  pass "2 回目の docker compose up -d --wait が成功 (${RESTART_SECONDS} 秒、ビルド無し)"
else
  RESTART_SECONDS=$((SECONDS - RESTART_START))
  fail "2 回目の docker compose up -d --wait が失敗 (${RESTART_SECONDS} 秒)"
  docker compose ps
fi

http GET "$GATEWAY/jwks.json"
eq "再起動後も /jwks.json が 200" 200 "$HTTP_CODE"
eq "グループ公開鍵 x が 1 回目と同じ" "$JWKS_X_FIRST" "$(jsonget "$HTTP_BODY" 'd.keys[0].x')"

sign_on alice password123 "itest-restart-$$"
ok "再起動後もサインオンが成功する" "$SIGN_ON_STATUS"
ok "access_token が返る" "$([ -n "$SIGN_ON_TOKEN" ] && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
echo
echo "================================================"
printf '結果: %s%d passed%s, %s%d failed%s (合計 %d)\n' \
  "$C_PASS" "$PASSED" "$C_OFF" \
  "$([ "$FAILED" -gt 0 ] && printf '%s' "$C_FAIL")" "$FAILED" "$C_OFF" \
  "$((PASSED + FAILED))"
echo "初回起動 (ビルド込み): ${UP_SECONDS} 秒 / 再起動 (ビルド無し): ${RESTART_SECONDS:-n/a} 秒"
echo "全体所要: ${SECONDS} 秒"
echo "================================================"

[ "$FAILED" -eq 0 ] || exit 1
