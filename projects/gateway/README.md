# gateway — OAuth プロキシ + OIDC/OAuth エンドポイント + デモ UI 配信

PASTA 分散 IdP の **フロント**。ブラウザ / RP フロントからの要求を受け、FROST の
2 ラウンドを `node` コンテナ群にオーケストレーションし、OAuth の Discovery と JWKS を
公開し、React 製のデモ UI を静的配信します。

`docs/container-split.md` 第 6 節と **第 14 節 (OAuth 化)** の契約に対応するコンポーネント
です。スコープは **OAuth 2.0 認可コードフロー + DPoP (RFC 9449)** で、OIDC の id_token は
**廃止**されました。

**このゲートウェイはユーザー状態を一切持ちません** (契約 第 14.2 節)。authorize セッション、
code ストア、refresh_token ストア、`sub`、認証状態のいずれも保持しません。gateway が行うのは、

1. `/api/pasta/sign-on` で FROST 2 ラウンドを中継し、ブラウザが **認証アサーション**
   (= 認可コード) を組み立てられるようにする。
2. `/token` で受け取った code (=アサーション) または refresh_token と DPoP proof をノードへ
   中継し、各ノードが平文で返す署名シェア `z_i` を合成して **アクセストークン**と**次の
   refresh_token** を組み立てる。

の 2 つだけです。**refresh_token はノードのグループ署名付き JWT** (`typ: refresh+jwt`) で、
gateway ではなくノードだけが発行できます。gateway は素通しします。

**gateway はパスワードも `h_i` も鍵シェアも持ちません。** ノードから返るのは `h_i` で
暗号化されたシェア `ct_i` (sign-on) か、`cnf.jkt` に束縛済みのトークンのシェア `z_i`
(token) だけです。パスワードを知るクライアントだけがアサーションを組み立てられ、rp の
DPoP 秘密鍵を持つブラウザだけがトークンを行使できます。`/api/pasta/sign-on` のボディに
`password` を入れて送っても、gateway は `username` と `blinded` しか読まないため単に
無視します (ログにも出ません)。

> **ISSUER は node と必ず一致させること。** ノードは `iss`・アサーションの `aud`・DPoP の
> `htu` (`<ISSUER>/token`) を自分の `ISSUER` で検証します。gateway が別の `ISSUER` を
> 名乗ると、アサーションもアクセストークンも組み上がりません (契約 第 2 節)。

## 起動方法

### ローカル

```bash
npm install
npm test
npm run build

# デモ UI を先にビルドしておく (gateway はビルド済みの成果物を配信するだけ)
cd ../demo && npm ci && npm run build && cd ../gateway

ISSUER=http://localhost:3000 \
NODE_URLS=http://localhost:4001,http://localhost:4002,http://localhost:4003 \
GROUP_CONFIG=../dealer/sample-output/group.json \
DEMO_DIST=../demo/dist \
RP_ORIGIN=http://localhost:3001 \
npm start
```

`npm run dev` はビルド無しで `tsx` から同じものを起動します。先に `dealer` が
`group.json` を書き、`node` が 3 台 (同じ `ISSUER` で) 起動している必要があります。

```bash
curl -s http://localhost:3000/health
```

### Docker

**ビルドコンテキストはリポジトリルート**です (デモ UI も同梱するため)。

```bash
docker build -f projects/gateway/Dockerfile -t pasta-gateway .

docker run -d --name gateway -p 3000:3000 \
  -e ISSUER=http://localhost:3000 \
  -e NODE_URLS=http://node1:4001,http://node2:4002,http://node3:4003 \
  -e GROUP_CONFIG=/secrets/group.json \
  -e RP_ORIGIN=http://localhost:3001 \
  -v "$PWD/projects/dealer/sample-output:/secrets:ro" \
  pasta-gateway
```

`node:22-alpine` の 4 ステージ構成 (demo UI ビルド / gateway ビルド / production 依存 /
ランタイム)。ランタイムには `dist/`、production 依存、`/app/ui` のデモ UI だけが入り、
非 root (`node` ユーザー) で起動します。`HEALTHCHECK` は `/health` を叩きます
(契約 第 8 節の `--interval=5s --timeout=3s --start-period=3s --retries=3`)。`SIGTERM` で
リスナーを閉じ、処理中の要求を終えてから exit 0 します。

## 環境変数

| 変数 | 既定 | 意味 |
|---|---|---|
| `PORT` | `3000` | 待受ポート。整数 (0–65535) 以外は起動時エラー |
| `ISSUER` | `http://localhost:${PORT}` | JWT の `iss`、Discovery の `issuer`、DPoP の `htu` の基底。**末尾スラッシュ無し**。**node と同一値にすること** |
| `NODE_URLS` | `http://localhost:4001,http://localhost:4002,http://localhost:4003` | カンマ区切り。**順序と nodeId は対応しない** (下記「ノード発見」) |
| `THRESHOLD` | `group.json` の `threshold` | quorum。明示すると `group.json` の値を上書きする |
| `GROUP_CONFIG` | `/secrets/group.json` | dealer 出力。`groupPublicKey` (hex 64) と `keyId` を読む |
| `DEMO_DIST` | `/app/ui` | ビルド済みデモ UI のディレクトリ |
| `RP_ORIGIN` | `http://localhost:3001` | `/token`・`/jwks.json` の CORS で許可するオリジン (契約 第 14.4 節) |
| `DEMO_LOG` | `1` | デモログ (下記)。`0` のときだけ無効、それ以外の値は有効 |
| `FORCE_COLOR` | (イメージでは `1`) | デモログの色。`0` で無色。`NO_COLOR` が設定されていれば無条件で無色 |

`group.json` は起動時に一度だけ読みます。`keyId` は JWKS の `kid` になります。トークン
ヘッダの `kid` は `pasta-group-key-1` 固定なので、dealer を `--key-id` で別の値にすると
RP が `kid` で鍵を引けなくなります (起動時に警告)。

## ノード発見

`NODE_URLS` は**順不同のリスト**です。gateway は起動時に各 URL の `GET /health` を叩き、
応答の `nodeId` でそのノードの識別子を知ります。まだ起動していないノードは 1 秒間隔で
最大 30 回再試行し、すべての URL が応答するまで待ちます。各ノードの `groupPublicKey` を
`group.json` と突き合わせ、別の鍵セレモニーのノードや同じ `nodeId` を名乗る URL は拒否
します。

起動後にノードが落ちた場合、`/api/pasta/sign-on` と `/token` は `participants` の指定が
無ければ **実際に commit を返したノード**で quorum を組みます。3 台中 1 台が落ちていても
2-of-3 で成功し、閾値を下回ってはじめて 400 になります。`/token` は 2 つの署名 (access /
refresh) を作るので `/commit` を各ノード 2 回呼びますが、両方とも同じ参加ノード集合で
行うので、2 つのシェアが同じ集合で合成されます。

## HTTP API

バイト列は **base64url (パディング無し)**、`z_i` スカラーは 64 桁小文字 hex (big-endian)、
`Uint8Array` を JSON に直接入れることはありません (契約 第 3 節)。

| Method | Path | 備考 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OAuth Discovery (`response_types_supported:["code"]`, `grant_types_supported:["authorization_code","refresh_token"]`, `token_endpoint`, `dpop_signing_alg_values_supported:["EdDSA"]`) |
| GET | `/jwks.json` | グループ公開鍵 1 本の JWK Set (RFC 8037, `kty=OKP` / `crv=Ed25519`)。CORS 対応 |
| GET | `/authorize` | `response_type=code`。検証して `/demo?step=login&c=…&dpop_jkt=…&client_id=…&redirect_uri=…&scope=…&state=…` へ meta refresh。`dpop_jkt` 必須。チャレンジ `c` を生成 (状態は保存しない) |
| POST | `/api/pasta/sign-on` | `ProxySignOnRequestBody` → `ProxySignOnResult` (b64u 化)。`clientId`・`nonce` (=`c`) 必須、`scope` 任意 |
| POST | `/token` | `application/x-www-form-urlencoded` + ヘッダ `DPoP: <proof>`。両 grant。応答 `{access_token, token_type:"DPoP", expires_in, refresh_token, scope}` |
| OPTIONS | `/token`, `/jwks.json` | CORS プリフライト (204) |
| GET | `/`, `/demo`, `/assets/*` | 静的配信 (`DEMO_DIST` 配下) |
| GET | `/health` | `{ "status", "nodes":[{nodeId,url,healthy}] }` |

**廃止**: `/api/pasta/refresh`、`/demo/rp-callback`、`/api/pasta/browser-sign-on`、`/rp`、
`/rp/callback`、`/authorize/complete`。id_token ごと廃止されています。

### `POST /token` (契約 第 14 節)

`grant_type` で 2 つの grant を受けます。

- `grant_type=authorization_code&code=<アサーション JWT>&client_id&redirect_uri`
- `grant_type=refresh_token&refresh_token=<node 署名付き JWT>`

いずれもヘッダ `DPoP: <proof>` (RFC 9449、`htm=POST`, `htu=<ISSUER>/token`) が必須です。

処理手順:

1. `DPoP` ヘッダから proof を取り出す (無ければ `invalid_dpop_proof`)。
2. credential (code=アサーション、または refresh_token) をデコードして `cnf.jkt` を取り出す。
3. **二重防御**: `verifyDPoPProof` で proof の署名・`htm`・`htu`・`iat` を検証し、proof の
   jwk サムプリントが credential の `cnf.jkt` と一致することを確認する (ノードも独立に検証)。
4. 全参加ノードに `/commit` を **2 回** (access 用と refresh 用) 呼び、`/sign` を並列で叩く。
   `claims` は gateway が生成 (`iat=now`, `exp=iat+3600`, `jti=乱数`, `refreshExp=iat+30日`)。
5. 各ノードが返す `at.z_i` / `rt.z_i` (平文) をそれぞれ **別のコミットメント集合で** 合成し、
   access_token と refresh_token の 2 つの JWT を組み立てる。

**署名対象の byte 一致**: gateway は node と同じ凍結 `createSigningInput` を、node と同じ
ヘッダ・ペイロードに対して呼びます。`deterministicJsonStringify` がキーを辞書順に並べるので、
両者の署名対象バイト列は一致し、シェアは JWKS で検証できる署名に合成されます。

- access token ヘッダ `{alg:"EdDSA", typ:"at+jwt", kid}`、ペイロード
  `{iss, sub, aud:client_id, scope, cnf:{jkt}, iat, exp, jti}` (辞書順)。
- refresh token ヘッダ `{alg:"EdDSA", typ:"refresh+jwt", kid}`、ペイロード
  `{iss, sub, cnf:{jkt}, client_id, scope, iat, exp}` (辞書順)。

`sub`・`client_id`・`scope`・`cnf.jkt` は credential から読み、`iss` は gateway の `ISSUER`、
`iat`/`exp`/`jti`/`refreshExp` は gateway が pin します。gateway は署名を偽造できず (鍵シェアを
持たない)、`cnf.jkt` に束縛されたトークンしか出せません。

エラーは 4xx + `{error, error_description}` (RFC 6749)。`invalid_request` (grant/フィールド
不正)、`unsupported_grant_type`、`invalid_dpop_proof` (proof 欠落・検証失敗・jkt 不一致)、
`invalid_grant` (credential 不正・ノード拒否・quorum 不足)。

### `nonce` (=チャレンジ `c`) と `clientId` は必須

`/api/pasta/sign-on` は `clientId` と `nonce` が**非空文字列でなければ 400** です。どちらも
アサーションのペイロードに載るためで、参照実装の `deterministicJsonStringify` は
`nonce: undefined` を `"nonce":undefined` (不正 JSON) と書き出します。`jwt.ts` はコピー凍結
なので gateway の入口で防ぎます。`scope` は空でも構いませんが文字列でなければなりません
(未指定は `""` とみなす)。

### `dpop_jkt` (契約 第 13 節)

`/authorize` は `dpop_jkt` を **必須** とします。RP フロントの DPoP 公開鍵の RFC 7638
サムプリントで、`^[A-Za-z0-9_-]{43}$` に一致しなければ 400 です。検証を通った値は `/demo`
への引き継ぎ URL に `&dpop_jkt=<jkt>` として乗り、デモ UI がそれを `cnfJkt` に使います。
`/authorize` はチャレンジ `c` (乱数) も生成し `&c=<c>` として渡します。**状態は保存しません。**

`src/gateway/oidc.ts` は第 13 節から byte 凍結の対象外です。参照実装からの差分は code フロー
対応 (`response_type=code`、`response_mode`/id_token 用 `nonce` 必須の削除、discovery の更新)
と `dpop_jkt`・`c` の引き継ぎです。

### CORS (契約 第 14.4 節)

`/token` と `/jwks.json` は rp オリジンからクロスオリジンで呼ばれます。

| エンドポイント | 許可 |
|---|---|
| `POST /token` | `Access-Control-Allow-Origin: <RP_ORIGIN>`、`Allow-Methods: POST`、`Allow-Headers: DPoP, Content-Type`、プリフライト 204 |
| `GET /jwks.json` | `Access-Control-Allow-Origin: <RP_ORIGIN>`、`Allow-Methods: GET` |

`DPoP` は単純ヘッダではないので、プリフライトの `Access-Control-Allow-Headers` に無いと
ブラウザはリクエストを送りません。Cookie は使わないので `Allow-Credentials` は不要です。

### ステータスコード

| Code | いつ |
|---|---|
| 200 | 成功 |
| 204 | `OPTIONS` (CORS プリフライト) |
| 400 | 必須フィールド欠落、`/authorize` パラメータ不正、`/token` のエラー (`{error, error_description}`)、プロキシ拒否、JSON でないボディ |
| 403 | 静的配信でディレクトリ外へ出ようとしたパス |
| 404 | 不明なパス |
| 413 | リクエストボディが 1MB を超えたとき |
| 500 | 想定外。ボディは `{ "error": "Internal server error" }` |
| 503 | `/health` で健全ノードが閾値未満 (`status: "degraded"`) |

パスワード誤りに gateway は関与しません。ノードは全台正常に応答し、AEAD 復号はブラウザ側で
失敗します。gateway から見ると成功したサインオンと区別が付きません。

### 静的配信

配信するのは `/` と `/demo` (どちらも `index.html`)、`/assets/...` だけです。解決後のパスが
`DEMO_DIST` の外に出る場合は 403 で拒否します (`..` は解決後の位置、シンボリックリンクは
`realpath` で判定)。

## デモログ

契約 第 10 節の圧縮形式 (1 イベント = 1〜2 行、英語) で、gateway が何を受け取り、何を中継し、
何を構造的に持ち得ないかを stdout に出します。gateway の色は**マゼンタ**。値は base64url の
先頭 8 文字 (access_token は `cnf.jkt` 束縛なので先頭 16 文字まで出してよい)。

```
[gateway] ● up      t=2/3 nodes=3 issuer=http://localhost:3000   holds: group pubkey, kid=pasta-group-key-1   never: s_i, k_i, h_i, pw
[gateway] authorize client_id=demo_client nonce=<c> state=rp-demo dpop_jkt=Rupx_EC1  → redirect /demo
[gateway] sign-on   sess=8fa90b5e round=ef54f65f user=alice nonce=<c>  ← A mNDkmKAj  jkt y7VfmjvC  (no pw)
                    round1 (D,E)×3 → round2 ← B_i×3 ct_i×3 (no h_i, cannot decrypt) → relayed as-is
[gateway] token     grant=authz  ← code(assertion) eyJhbGci + DPoP ✓  → 2×/commit ×3 → /sign → access_token eyJhbGciOiJhdCtq (cnf.jkt=y7VfmjvC) + refresh_token
[gateway] jwks      public only
[gateway] discovery public only
```

出るイベント: 起動 (`● up`)、`authorize`、`sign-on` (2 行)、`token`、`jwks`、`discovery`、
拒否 (`✖ <event> rejected: <reason>`)。`never:` は起動行にだけ出ます (id_token は廃止された
ので never には含めません。access_token / refresh_token は `cnf.jkt` 束縛のためログに出して
よく、never にも入れません)。ノードが 1 台落ちて quorum を組み直したときは 2 行目 / token 行が
`(node3 unreachable, excluded)` を含みます。

`password` はここに出しようがありません。gateway は受け取らず、`src/demolog.ts` のイベント型は
どれも `password?: never` を宣言しています。

環境変数: `DEMO_LOG=0` で無効。色は `NO_COLOR` → `FORCE_COLOR=0` → `FORCE_COLOR` (0 以外) →
TTY 判定 の優先順位。

## テスト

```bash
npm test
```

- `tests/dpop_and_oidc.test.ts` — DPoP (RFC 9449) / form_post / OAuth Discovery / `/authorize`
  (code フロー) の単体テスト。
- `tests/static.test.ts` — 静的配信のパス解決とトラバーサル拒否。
- `tests/e2e.test.ts` — フィクスチャ 3 ノード分の**フェイクノード HTTP サーバ**と gateway を
  ポート 0 で起動し、実ソケット越しに検証する。`/authorize` の code フロー、`/api/pasta/sign-on`
  → テストヘルパー (`helpers/sign-on-client.ts`) でのアサーション合成 → `/token`
  (authorization_code) が access_token と refresh_token を返し JWKS で検証できること・`cnf.jkt`
  / `aud` / `sub` / `typ` が正しいこと、refresh grant、proof 無しで 400、proof の鍵が code の
  `cnf.jkt` と不一致で 400、改竄 code で 400、`OPTIONS /token` / `/jwks.json` の CORS、ノード
  1 台停止でも 2-of-3 で `/token` 成功、`/health`、静的配信、デモログに `token grant=authz` と
  access_token が出てパスワードが出ないこと。
- `tests/demolog.test.ts` — デモログ単体。

フェイクノードは `tests/helpers/protocol/node.ts` (§14 対応済み `node/src/protocol/node.ts` の
byte 一致コピー) を第 5・14 節の HTTP API (`/commit`・`/sign-on`・`/sign`) で包んだものです。
`helpers/sign-on-client.ts` はブラウザ SDK 相当のアサーション合成 (凍結 crypto を使用) を
テスト内で行います (凍結 `client-sdk/client.ts` は id_token を組み立てるため §14 では使えず、
削除しました)。`node/` プロジェクトからは何も import していません。

## ここに無いもの

鍵生成 (それは `dealer`)、シェアの保持と署名・アサーション/トークンの検証 (それは `node`)、
RP のランディングと `/callback` (それは `rp`)。gateway はユーザー状態を持たず、id_token も
`/rp` も持ちません。
