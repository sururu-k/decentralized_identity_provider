# rp — ZK-App Portal (Relying Party)

PASTA 分散 IdP に対する **OAuth 2.0 クライアント (認可コードフロー + DPoP)** のデモ実装。
`docs/container-split.md` 第 7 節の契約に対応するコンポーネントで、フローの定義は第 14 節です。

このサービスの **サーバーは HTML を配るだけ** です。認可コードをアクセストークンに交換する
`POST /token` も、`GET /jwks.json` も、Ed25519 署名検証も、すべて **ブラウザ内のインライン
JavaScript** が行います。理由は 1 つで、DPoP 秘密鍵が rp オリジンの IndexedDB にしか無いから
です (契約 第 13 節)。鍵を持たないサーバーは proof を作れず、proof が無ければノードは署名しない
ので、rp サーバーがトークン取得を代行することは構造的にできません。

その結果、rp サーバーは **アクセストークンを一度も見ません**。デモログの `● up` 行の `never:`
に `access_token (handled in browser only)` が入っているのはそのためです。

**ランタイム依存はゼロ** (`node:http` / `node:crypto` / `node:url` のみ)。ブラウザ側も
ビルド無し・依存ゼロのインライン JS です。

## 起動方法

### ローカル

```bash
npm install
npm run dev            # tsx で src/index.ts を起動
# または
npm run build && npm start
```

### Docker

```bash
docker build -t pasta-rp ./projects/rp
docker run --rm -p 3001:3001 \
  -e ISSUER=http://localhost:3000 \
  -e RP_BASE_URL=http://localhost:3001 \
  pasta-rp
```

`HEALTHCHECK` は `/health` を叩きます (alpine に curl が無いため `node -e "fetch(...)"` を使用)。
コンテナは非 root (`node` ユーザー) で起動します。

## 環境変数

| 変数 | 既定 | 意味 |
|---|---|---|
| `PORT` | `3001` | 待受ポート。整数 (0–65535) 以外・空文字は既定値にフォールバックする |
| `RP_BASE_URL` | `http://localhost:3001` | `redirect_uri` の組み立てに使う (`${RP_BASE_URL}/callback`) |
| `ISSUER` | `http://localhost:3000` | `/authorize`・`/token`・`/jwks.json` の基底 URL、かつブラウザが照合する `iss` |
| `CLIENT_ID` | `demo_client` | `client_id` パラメータと、ブラウザが照合する `aud` |

`IDP_INTERNAL_URL` は **削除しました**。サーバー側の JWKS 取得が無くなり、`/jwks.json` を
fetch するのはブラウザだけになったからです。ブラウザから見える URL でなければ意味がないので、
compose 内部ホスト名 (`http://gateway:3000`) を指す設定は存在してはいけません。この変数が環境に
残っていても無視されます (`configFromEnv` は読みません)。

`ISSUER` と `RP_BASE_URL` は末尾スラッシュを取り除いてから使うので、`http://localhost:3000/`
と書いても URL が `//` になりません。

## エンドポイント

| Method | Path | 説明 |
|---|---|---|
| GET | `/` | ランディングページ。ページ内で DPoP 鍵を用意し、ログインボタンが `${ISSUER}/authorize?response_type=code&...&dpop_jkt=<jkt>` へ遷移する |
| GET | `/callback?code&state` | トークン取得ページ。`code` / `state` / `issuer` / `client_id` / `redirect_uri` を `data-` 属性に埋めた HTML を返すだけ。**サーバーは `/token` を呼びません** |
| GET | `/health` | `{ "status": "ok" }` |

`POST /callback` (旧 form_post 受信) は削除しました。id_token ごと廃止されています (契約 第 14 節「廃止」)。

### `GET /`

`/authorize` の URL を組み立ててボタンに貼ります。

```
${ISSUER}/authorize
  ?response_type=code
  &client_id=${CLIENT_ID}
  &redirect_uri=${RP_BASE_URL}/callback   (percent-encoded)
  &scope=openid%20profile%20email
  &state=<リクエスト毎にランダム 128 bit>
  &dpop_jkt=<ページ内で計算したサムプリント>   (インライン JS が付ける)
```

- `response_mode` と `nonce` は付けません。OIDC ではなく OAuth なので `id_token` も
  `form_post` も無く、リプレイ防止は認可サーバーが発行するチャレンジ `c` が担います (第 14.1 節)。
- `scope` に `openid` は **残しています**。gateway の既存 `/authorize` が `openid` を要求している
  可能性があり、そこは rp の担当範囲外だからです。
- `state` はサーバーが `crypto.randomBytes(16)` で生成し、URL と `data-state` 属性の両方に置きます。
  インライン JS がそれを `sessionStorage["pasta-rp-state"]` に保存し、`/callback` で照合します。
  照合するのは **ブラウザ** です (rp サーバーはリクエストをまたぐ状態を一切持ちません)。

#### DPoP 鍵はこのページが持つ (契約 第 13 節)

1. `crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])` で鍵ペアを作る。
   `extractable=false` なので秘密鍵のバイト列は JS からも取り出せません。
2. 鍵ペアの `CryptoKey` を IndexedDB (`pasta-rp` データベースの `dpop` ストア、キー `current`)
   に保存する。既にあれば作り直さず再利用します。
3. 公開 JWK の `{crv, kty, x}` を**辞書順**で JSON 化して SHA-256 → base64url = RFC 7638 の
   jkt。これを画面に出し、ログインリンクの `href` に `&dpop_jkt=<jkt>` を付けてボタンを有効にします。

jkt が確定するまでボタンは `aria-disabled="true"` のままで `href` を持ちません
(`/authorize` は `dpop_jkt` 無しでは 400 を返すため)。WebCrypto が Ed25519 に対応していない、
または IndexedDB が使えない環境では、ボタンを無効のままにして理由を画面に出します。

### `GET /callback?code&state`

| 状況 | ステータス | 表示 |
|---|---|---|
| `code` あり | 200 | トークン取得ページ (インライン JS がこの後の全工程を行う) |
| `error=...` (RFC 6749 4.1.2.1) | 400 | 認可失敗ページ。`error` / `error_description` / `state` を表示し、トークン取得は行わない |
| `code` も `error` も無い | 400 | Bad Request |

**`code` は不透明値ではなく、認証アサーション JWT そのものです** (契約 第 14 節の改定)。ノードの
グループ署名が付いた `xxx.yyy.zzz` で、数百バイトあります。rp は中身を一切解釈せず、切り詰めず、
バイト列のまま `data-code` に入れて `/token` へ渡します。検証するのは gateway とノードです
(rp はグループ公開鍵を持たないので検証できませんし、する必要もありません)。

長い URL になるので 1 点だけ注意があります。Node の HTTP パーサーは既定でリクエストヘッダ全体を
16 KB に制限します (`--max-http-header-size`)。アサーションが数百バイトなら余裕がありますが、
将来クレームが増えて URL がこの上限に近づくと `/callback` が 431 を返すようになります。

サーバーが行うのは 5 つの値のエスケープだけです。

```html
<main id="token-flow"
      data-code="…" data-state="…"
      data-issuer="…" data-client-id="…" data-redirect-uri="…">
```

#### インライン JS の責務 (契約 第 14.1 節 step 9〜13)

`src/html.ts` の `TOKEN_SCRIPT` (`PastaToken` 名前空間) と、それを DOM に繋ぐ `TOKEN_PAGE_SCRIPT`。

1. **state 照合** — `sessionStorage["pasta-rp-state"]` と `data-state` を比較。不一致・未保存は
   その場で失敗表示にして `/token` を呼びません。
2. **DPoP proof** — IndexedDB の鍵で 1 リクエストにつき 1 つ署名します。

   ```
   header  {"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":"…"}}
   payload {"jti":"<128bit base64url>","htm":"POST","htu":"<ISSUER>/token","iat":<unix秒>}
   署名     crypto.subtle.sign("Ed25519", privateKey, ASCII(header.payload))
   ```

   base64url は自前実装 (`btoa` + 文字置換、パディング除去)。`jti` は毎回新しい値です。
3. **`POST <ISSUER>/token`** — `Content-Type: application/x-www-form-urlencoded`、`DPoP: <proof>`。
   本体は `grant_type=authorization_code&code=<アサーション JWT>&client_id=…&redirect_uri=…`。
   `code` は `data-code` から読んだ文字列をそのまま入れます (フォーム符号化されるので、
   JWT のドットや長さは問題になりません)。
   応答 `{access_token, token_type:"DPoP", expires_in, refresh_token, scope}`。
   非 2xx は `{error, error_description}` として画面に出します (例外にしません)。
4. **`GET <ISSUER>/jwks.json`** — `kid` で鍵を選び
   `crypto.subtle.importKey("jwk", {kty:"OKP",crv:"Ed25519",x}, {name:"Ed25519"}, false, ["verify"])`
   → `crypto.subtle.verify("Ed25519", …)`。
5. **クレーム検証** — 順に `typ === "at+jwt"`、`alg === "EdDSA"`、Ed25519 署名、`iss === ISSUER`、
   `aud` に `client_id` を含む、`exp` 未経過、`cnf.jkt` === 自鍵の jkt。1 項目ずつ ✓ / ✖ を並べて
   表示し、最初に失敗した項目で止めます (署名が通っていないトークンの `iss` を論じても意味がないため)。
6. **表示** — access_token 全文、`token_type` / `expires_in` / `scope`、`refresh_token` は先頭 8 文字、
   自鍵の jkt、検証結果の一覧、クレーム JSON。
7. **リフレッシュボタン** — 同じ手順を `grant_type=refresh_token&refresh_token=…` で実行し、
   **新しい proof** を付けて送り、表示を更新します。認可サーバーが refresh_token を
   ローテーションする前提なので、成功のたびに保持している値を差し替えます。

外部由来の値は例外なく `textContent` で描画します。`innerHTML` / `outerHTML` /
`insertAdjacentHTML` / `document.write` はインライン JS に 1 か所もありません
(テストで機械的に確認しています)。

#### gateway 側に必要な CORS

`/token` と `/jwks.json` は rp オリジンから **クロスオリジンで** 呼ばれます (契約 第 14.4 節)。

| エンドポイント | 必要な許可 |
|---|---|
| `POST /token` | `Access-Control-Allow-Origin: <rp origin>`、`Access-Control-Allow-Methods: POST`、`Access-Control-Allow-Headers: DPoP, Content-Type`、プリフライト `OPTIONS` に 204 |
| `GET /jwks.json` | `Access-Control-Allow-Origin: <rp origin>` (または `*`)、`Access-Control-Allow-Methods: GET` |

`DPoP` は CORS の単純ヘッダではないので、**プリフライトの `Access-Control-Allow-Headers` に
`DPoP` が無いとブラウザはリクエスト自体を送りません**。Cookie は使わないので
`Access-Control-Allow-Credentials` は不要です。

## デモログ (`docs/container-split.md` 第 10 節)

デモでは node / gateway / rp / ブラウザのログを並べて表示し、各コンポーネントが何を知り得るかを
見せます。rp は圧縮形式 (1 イベント = 1 行、英語) で接頭辞 `[rp]` を付けて stdout に出します
(`src/demolog.ts`)。

```
[rp]      ● up      issuer=http://localhost:3000   holds: nothing (HTML only)   never: pw, A, B_i, ct_i, any node traffic, access_token (handled in browser only)
[rp]      landing   state=V65uejRYYjhrmxo0hKkzLQ  → authorize URL
[rp]      callback  state=V65uejRYYjhrmxo0hKkzLQ  ← code(assertion) eyJhbGci (query, via browser redirect)  → page with token script
```

失敗時は 1 行だけ:

```
[rp]      ✖ callback rejected: no code in the redirect query string
[rp]      ✖ callback rejected: authorization server returned error=access_denied (user refused)
```

`jwks` イベントは **無くなりました** (サーバーが JWKS を取りに行かなくなったため)。`code` は
使い捨ての署名付きバイト列なので先頭 8 文字に切り詰め (`code(assertion)` と書くのは、それが
rp には作れない署名済みの主張であってデータベースのキーではないことを示すため)、`state` は
公開の相関 id なので全文を出します。トークン交換の行は rp の列には出ません。ブラウザの列に出ます。

環境変数:

| 変数 | 既定 | 意味 |
|---|---|---|
| `DEMO_LOG` | `1` (Docker イメージの既定) | `0` を指定すると `[rp]` ログを止め、従来の運用ログのみにする |
| `FORCE_COLOR` | `1` (Docker イメージの既定) | `0` で無色。それ以外の値なら有色。未設定なら TTY 判定 |
| `NO_COLOR` | 未設定 | 空でない値を設定すると `FORCE_COLOR` より優先して色を無効化する |

色の優先順位は `NO_COLOR` → `FORCE_COLOR=0` → `FORCE_COLOR` (0 以外) → TTY 判定です。
`docker compose logs` は TTY にならないため、Dockerfile は既定で `DEMO_LOG=1` /
`FORCE_COLOR=1` を設定しています。色を消すには `FORCE_COLOR=0` を使ってください
(`NO_COLOR` は Node 本体が警告を出します)。

## テスト

```bash
npm test
```

### ブラウザが無い環境で、ブラウザのコードをどうテストしているか

このプロジェクトの中身はほぼインライン JavaScript です。TypeScript コンパイラは文字列の中を
見ませんし、この環境にブラウザはありません。そこで **`new Function` で取り出して Node の
WebCrypto で実行する** ことを、実ブラウザ確認の代替としています。Node 20 以降の
`globalThis.crypto.subtle` はブラウザと同じ WebCrypto API で、Ed25519 に対応しています。

`tests/token-script.test.ts` (`TOKEN_SCRIPT` = `PastaToken`):

- **base64url** — バイト列・UTF-8 文字列 (多バイト文字含む) の往復を `node:crypto` の
  `Buffer.toString("base64url")` と突き合わせ。長さの余り 0/1/2 全パターン。
- **proof 組み立て** — `PastaToken.createProof` が作った proof を、ヘッダの `jwk` から
  `crypto.createPublicKey({format:"jwk"})` で鍵を起こして `node:crypto` の `crypto.verify` で検証。
  ヘッダ/ペイロードの形 (RFC 9449 4.2)、`jwk` に `d` が無いこと、`jti` が毎回変わること、
  ペイロードを 1 バイト変えると検証が落ちることを確認。
- **JWT 分解** — 3 分割・JSON 化・署名バイト列 64 バイト。壊れた入力は例外。
- **クレーム検証** — テストが `node:crypto` の Ed25519 鍵で署名したアクセストークン
  (`typ: at+jwt`、`cnf.jkt` = proof 鍵の jkt) を `verifyAccessToken` が受理し、**改竄 / 別鍵署名 /
  `iss` 違い / `aud` 違い / 期限切れ / `exp` が数値でない / `cnf.jkt` 違い / `cnf` 欠落 /
  `typ` 違い / 未知 `kid` / 壊れた形式** をすべて拒否することを確認。`now` を注入できるので
  期限のテストは実時刻に依存しません。
- **結合テスト** — **フェイク gateway の HTTP サーバをポート 0 で起動** し、`PastaToken.obtainToken`
  を Node で実行します。フェイク gateway は `/token` で `DPoP` ヘッダの存在・`grant_type`・
  proof の署名・`htm` / `htu` を検証し、**proof のヘッダ JWK のサムプリントに束縛した** トークンを
  返します (つまり本当にその鍵で署名していないとトークンが出ません)。確認するのは
  成功パス、リフレッシュ (新しい proof / 新しい `jti` / ローテーション後の旧 refresh_token が
  `invalid_grant`)、`/token` の 400 が `error` / `error_description` として表に出ること、
  `DPoP` ヘッダを剥がすと発行されないこと、JWKS 取得不能時にトークンを失わずに報告すること、
  **600 バイト超のアサーション JWT を `code` として送っても、フォーム本体でバイト単位に保たれること**。
  フェイク gateway は `code` が 3 分割の JWT 形か (アサーション形か) だけを見ます。中身の検証は
  本物の gateway とノードの仕事です。
  IndexedDB (`material`) と `fetch` (`fetchImpl`) は引数なので、フェイクに差し替えられます。

`tests/dpop-script.test.ts` (`DPOP_SCRIPT` = `PastaDpop`):

- jkt が `node:crypto` で独立に計算した `{crv,kty,x}` 辞書順 JSON の SHA-256 base64url と一致すること
  (node 側 `calculateJwkThumbprint` とのバイト一致に相当。既知の公開鍵に対する固定値も突き合わせ)。
- 両ページの `<script>` の中身をすべて `new Function` でパースし、構文エラーが無いこと。
- 外部値の描画に `innerHTML` 系が使われていないこと。

`tests/rp.test.ts` — 実 HTTP のコンポーネントテスト。`/` の authorize URL のパラメータ
(`response_type=code`、`response_mode` / `nonce` が無いこと、`state` が毎回変わること)、
`/callback?code&state` が 200 で 5 つの `data-` 属性を持つこと、**300 バイト超のアサーション JWT が
`data-code` にバイト単位でそのまま入り、クレームが HTML に漏れないこと**、敵対的な `code` /
`state` / `error` がエスケープされること、`code` 欠落で 400、`error=access_denied` で認可失敗ページ、
`POST /callback` が 404、デモログの各行、`configFromEnv` / `portFromEnv`。

`tests/demolog.test.ts` — `src/demolog.ts` 単体 (無効化、8 文字切り詰め、色の優先順位、桁揃え、
`holds:` / `never:` が起動行にしか出ないこと)。

### ブラウザでしか確かめられない部分

以下は **この環境では実行できず、コードレビューによる確認に留まります**。

- **IndexedDB** — Node に実装がないため、`openDb` / `idbGet` / `idbPut` と、
  `ensureKeyPair` / `ensureKeyMaterial` の「保存済みの鍵を再利用する」経路。テストでは鍵素材を
  平のオブジェクトとして与えています。
- **`extractable=false` の `CryptoKey` を IndexedDB に構造化複製で保存できること** (仕様上は可能ですが、
  実ブラウザで確認していません)。
- **DOM 操作と表示** — `TOKEN_PAGE_SCRIPT` は構文チェックと文字列検査のみ。ボタンの有効化、
  ✓ / ✖ の描画、リフレッシュボタンのクリック動線。
- **CORS** — ブラウザのプリフライトは Node の `fetch` では発生しません。上表の許可ヘッダが
  正しいかは gateway に `/token` が実装された後、実ブラウザで確認する必要があります。
- **`sessionStorage`** — Node に無いため、state 照合の分岐はレビューのみ。

## ソース構成

```
src/
├── index.ts     # 環境変数の読み取りと listen
├── server.ts    # ルーティング (GET /, GET /callback, GET /health) と authorize URL の組み立て
├── config.ts    # 環境変数 → RpConfig
├── html.ts      # ページテンプレート + インライン JS (DPOP_SCRIPT / TOKEN_SCRIPT ほか)
└── demolog.ts   # デモログ (第 10 節の圧縮形式で stdout に出力)
```

`jwt.ts` と `jwks.ts` は **削除しました**。JWT の検証も JWKS の取得もブラウザに移ったためです。

`createRpServer(config)` は `listen` していない `http.Server` を返すので、テストからポート 0 で
起動できます。
