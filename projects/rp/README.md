# rp — ZK-App Portal (Relying Party)

PASTA 分散 IdP に対する **OpenID Connect Relying Party** のデモ実装。
`docs/container-split.md` 第 7 節の契約に対応するコンポーネント。

このサービスは IdP の内部を一切知りません。ID トークンの検証に使うのは
**gateway が公開する JWKS (`/jwks.json`) だけ** で、`secrets/group.json` は読みませんし、
IdP 側の暗号コード (`@noble/curves` など) も共有しません。JWT の分解は base64url +
`JSON.parse`、署名検証は `node:crypto` の `crypto.verify(null, ..., { key: jwk, format: "jwk" }, sig)`
による標準的な EdDSA (Ed25519) 検証です。つまり、ここで検証が通るトークンは
一般的な OIDC ライブラリでも同じように検証できます。

**ランタイム依存はゼロ** (`node:http` / `node:crypto` / `node:url` のみ)。

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

### docker compose

compose では JWKS 取得を compose 内ホスト名で行います。

```yaml
rp:
  build: ./projects/rp
  ports: ["3001:3001"]
  environment:
    ISSUER: http://localhost:3000        # ブラウザから見える URL = JWT の iss
    IDP_INTERNAL_URL: http://gateway:3000 # サーバ側の JWKS 取得先
    RP_BASE_URL: http://localhost:3001
  depends_on:
    gateway: { condition: service_healthy }
```

## 環境変数

| 変数 | 既定 | 意味 |
|---|---|---|
| `PORT` | `3001` | 待受ポート。整数 (0–65535) 以外・空文字は既定値にフォールバックする |
| `RP_BASE_URL` | `http://localhost:3001` | `redirect_uri` の組み立てに使う (`${RP_BASE_URL}/callback`) |
| `ISSUER` | `http://localhost:3000` | `/authorize` の組み立てと `iss` 検証 |
| `IDP_INTERNAL_URL` | 未設定なら `ISSUER` | JWKS 取得先。compose では `http://gateway:3000` |
| `CLIENT_ID` | `demo_client` | `aud` 検証と `client_id` パラメータ |

## エンドポイント

| Method | Path | 説明 |
|---|---|---|
| GET | `/` | ランディングページ。ページ内で DPoP 鍵を用意し、「PASTA IdP でログイン」ボタンが `${ISSUER}/authorize?...&dpop_jkt=<jkt>` へ遷移する |
| POST | `/callback` | `application/x-www-form-urlencoded` で `id_token` を受け取り、検証して結果を HTML で表示。トークンの `cnf.jkt` と手元の鍵の jkt の一致もブラウザ側で示す |
| GET | `/health` | `{ "status": "ok" }` |

### `GET /`

`/authorize` の URL を組み立ててボタンに貼ります。

```
${ISSUER}/authorize
  ?client_id=${CLIENT_ID}
  &redirect_uri=${RP_BASE_URL}/callback   (percent-encoded)
  &response_type=id_token
  &response_mode=form_post
  &scope=openid profile email
  &nonce=<リクエスト毎にランダム>
  &state=<リクエスト毎にランダム>
  &dpop_jkt=<ページ内で計算したサムプリント>   (インライン JS が付ける)
```

`nonce` と `state` はリクエストごとに `crypto.randomBytes(16)` から生成します。
既存の gateway 実装にサーバ側の照合が無いため、このデモでも照合は行わず**表示のみ**です
(本番の RP ではセッションに保存して突き合わせる必要があります)。

#### DPoP 鍵はこのページが持つ (契約 第 13 節)

ランディング HTML には**依存ゼロ・ビルド無しのインライン JS** が入っています。やることは
3 つだけです。

1. `crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])` で鍵ペアを作る。
   `extractable=false` なので秘密鍵のバイト列は JS からも取り出せません。
2. 秘密鍵の `CryptoKey` を IndexedDB (`pasta-rp` データベースの `dpop` ストア、キー `current`)
   に保存する。既にあれば作り直さず再利用し、jkt を計算し直します。
3. 公開 JWK の `{crv, kty, x}` を**辞書順**で JSON 化して SHA-256 → base64url = RFC 7638 の
   jkt。これを画面 (`my DPoP jkt`) に出し、ログインリンクの `href` に `&dpop_jkt=<jkt>` を
   付けてボタンを有効にします。

jkt が確定するまでボタンは `aria-disabled="true"` のままで `href` を持ちません
(`/authorize` は `dpop_jkt` 無しでは 400 を返すため)。WebCrypto が Ed25519 に対応していない、
または IndexedDB が使えない環境では、ボタンを無効のままにして理由を画面に出します。

**秘密鍵は rp サーバにも gateway にもノードにも渡りません。** サーバに出て行くのは jkt
だけで、`id_token` の `cnf.jkt` は最初から rp オリジンの鍵に束縛されます。

### `POST /callback`

| 状況 | ステータス | 表示 |
|---|---|---|
| 検証成功 | 200 | 「認証成功」+ `sub` / `iat` / クレーム生データ |
| 署名不正・`iss` 不一致・`aud` 不一致・期限切れ・未知 `kid`・不正な形式 | 401 | 「認証失敗」+ 失敗理由 |
| `id_token` が無い | 400 | Bad Request |
| リクエストボディが 1 MB 超 | 413 | Payload Too Large |
| JWKS を取得できない | 502 | Bad Gateway |

検証項目:

1. **署名** — JWT ヘッダの `kid` で JWKS から鍵を選び (`kty: OKP`, `crv: Ed25519`, `alg` があれば `EdDSA`)、`crypto.verify` で Ed25519 検証。ヘッダの `alg` は `EdDSA` 必須。
2. **`iss`** — `ISSUER` と一致 (末尾スラッシュの有無だけは無視する。gateway 側は `ISSUER` を正規化しないため、
   両サービスに `ISSUER=http://localhost:3000/` を同じように設定しても検証が通るようにするための緩和)。
3. **`aud`** — `CLIENT_ID` を含むこと (文字列でも配列でも可)。
4. **`exp`** — 現在時刻より後。`iat` / `nbf` は 60 秒のクロックスキューを許容。

`nonce` (トークン内) と `state` (form_post のパラメータ) は表示のみで、検証には使いません。

表示には「トークンの `cnf.jkt`」「my DPoP jkt (この端末)」「DPoP 鍵の照合」の 3 行が並びます。
サーバがやるのは 1 行目 (トークンから読んだ値をエスケープして `data-cnf-jkt` に置く) だけで、
残り 2 行はインライン JS が IndexedDB の鍵から jkt を計算し直して埋めます。一致すれば ✓、
違えば ✖。鍵はサーバに送られません。

## JWKS の取得とキャッシュ

- 起動時ではなく **最初の `/callback` で** `${IDP_INTERNAL_URL}/jwks.json` を取得し、メモリにキャッシュします。
- キャッシュに無い `kid` が来たときだけ **1 回だけ再取得** します (鍵ローテーション対応)。再取得しても見つからなければ 401。
  キャッシュが空の状態で未知 `kid` が来た場合は、取得したばかりの文書に対する再取得は無意味なので 1 回の取得で打ち切ります。
- 再取得はキャッシュを**置き換えるのではなく、成功したときだけ差し替え**ます。存在しない `kid` のトークンを投げても、
  IdP が落ちている間にキャッシュ済みの鍵を失って既知の `kid` まで検証できなくなる、ということは起きません。
- `keys` の要素が JWK でない (`null`、文字列、`kty` 違い) 場合はその要素を無視します。使える鍵が無ければ 401 で、500 にはなりません。
- 取得に失敗した場合 (接続不能、非 200、JSON でない、`keys` が無い) は 502 を返し、キャッシュは更新しません。次のリクエストで再試行します。
- 同時に複数のリクエストが来ても取得は 1 回にまとめられます。

## デモログ (`docs/container-split.md` 第10節)

デモでは node / gateway / rp / ブラウザのログをターミナルに並べて表示し、「ブラウザ以外は
`id_token` を組み立てる材料を揃えられない」ことを見せます。そのため rp も他コンポーネントと
同じ圧縮形式 (1 イベント = 1〜2 行、英語) で、接頭辞 `[rp]` を付けて stdout に出力します
(`src/demolog.ts`)。イベント名は専用の桁に左詰めし、2 行目はその桁ぶん字下げします。

イベントは 4 つです。

- 起動 (`● up`) — 保持するもの (`holds:`) と構造的に持ち得ないもの (`never:`) を宣言する
  1 行。**この宣言はここにしか出しません**。
- `GET /` (`landing`) — `authorize` URL に載せる `nonce` / `state` の発行。
- `POST /callback` (`callback`) — form_post で届いた `id_token` の検証。1 行目が到着した
  もの、2 行目が公開鍵で検証した内容。検証に失敗した場合は 2 行目の代わりに
  `[rp]      ✖ callback rejected: <理由>` を出します。
- JWKS 取得 (初回・鍵ローテーション時の再取得) — `jwks      public only` の 1 行のみ。

出力例 (起動、`GET /`、成功する `POST /callback`):

```
[rp]      ● up      issuer=http://localhost:3000   holds: JWKS(kid) only   never: pw, A, B_i, ct_i, any node traffic
[rp]      jwks      public only
[rp]      landing   nonce=th0kTNgh9cebjoDhwOyv-g state=V65uejRYYjhrmxo0hKkzLQ  → authorize URL
[rp]      callback  state=compact-2  ← id_token eyJhbGci (direct from browser, not via gateway)
                    JWKS kid=pasta-group-key-1 → Ed25519 ✓  iss ✓  aud ✓  exp 3598s  sub=usr_alice_12345
```

検証に失敗した場合の `POST /callback` は代わりに次の 2 行になります:

```
[rp]      callback  state=compact-3  ← id_token eyJhbGci (direct from browser, not via gateway)
[rp]      ✖ callback rejected: Ed25519 signature verification failed
```

`id_token` はセッション限りの使い捨て値なので先頭 8 文字に切り詰めます (`…` は付けません)。
OIDC の `nonce` / `state` と、検証済みクレームの `sub` は公開値であり 1 回のログインを列を
またいで追跡する鍵になるため、切り詰めずに全文を表示します。

環境変数:

| 変数 | 既定 | 意味 |
|---|---|---|
| `DEMO_LOG` | `1` (Docker イメージの既定) | `0` を指定すると `[rp]` ログを止め、従来の運用ログのみにする |
| `FORCE_COLOR` | `1` (Docker イメージの既定) | `0` で無色。それ以外の値なら有色。未設定なら TTY 判定 |
| `NO_COLOR` | 未設定 | 空でない値を設定すると `FORCE_COLOR` より優先して色を無効化する |

色の優先順位は `NO_COLOR` → `FORCE_COLOR=0` → `FORCE_COLOR` (0 以外) → TTY 判定です。
`docker compose logs` はパイプ経由になり TTY にならないため、Dockerfile は既定で
`DEMO_LOG=1` / `FORCE_COLOR=1` を設定しています。色を消したい場合は `FORCE_COLOR=0` を
使ってください (`NO_COLOR` は Node 本体が警告を出します)。

## テスト

```bash
npm test
```

`tests/rp.test.ts` はすべて実 HTTP 経由のコンポーネント e2e です。
vitest 内で `node:crypto` の `generateKeyPairSync("ed25519")` で鍵を作り、
フェイク JWKS サーバと rp サーバをそれぞれポート 0 で起動して次を確認します。

- 正しい JWT → 200、成功表示、`sub` の表示
- 改竄 / 別鍵署名 / `iss` 不一致 / `aud` 不一致 / 期限切れ / 未来の `iat` / `alg` 不正 / 不正形式 / 未知 `kid` → 401 と失敗表示
- `id_token` 欠落 → 400
- JWKS 取得不能・JWKS が 500 → 502、復旧後は 200
- 未知 `kid` での再取得が 1 回だけであること、既知 `kid` ではキャッシュが使われること
- 再取得が失敗してもキャッシュ済みの鍵が残り、既知 `kid` は検証できること
- `iss` が末尾スラッシュだけ違うトークンを受理すること
- 成功 / 失敗 / 400 / 502 のどのページからも `/` に戻れること
- `/` に `redirect_uri=...%2Fcallback` と `response_mode=form_post` が含まれ、`nonce` / `state` が毎回変わること
- 敵対的な `sub` / `state` / `cnf.jkt` が HTML にエスケープされること
- `/` に鍵生成とサムプリント計算のインライン JS があり、ログインリンクが `href` を持たないこと
- `/callback` にトークンの `cnf.jkt` と照合用の要素・JS があること
- ボディが 1 MB を超えたとき、接続を切らずに 413 を返すこと
- `exp` が数値でないトークンを拒否すること
- `keys` に不正な要素が混ざっていても 401 で済むこと
- `portFromEnv` / `configFromEnv` の既定値とフォールバック

`tests/dpop-script.test.ts` はインライン JS のテストです。ブラウザを起動できないので、
次の 2 つで代替します。

- `DPOP_SCRIPT` を `new Function` で評価し、**Node の WebCrypto** (`crypto.subtle`、
  Node 20 以上で Ed25519 対応) で作った鍵の jkt を計算させ、`node:crypto` で独立に計算した
  `{crv,kty,x}` 辞書順 JSON の SHA-256 base64url と一致することを確認します。これが
  `projects/node/src/client-sdk/dpop.ts` の `calculateJwkThumbprint` とのバイト一致に相当します
  (node プロジェクトは import しません)。既知の公開鍵に対する固定値も突き合わせます。
- 両ページの `<script>` の中身をすべて取り出して `new Function` でパースし、構文エラーが
  無いことを確認します。

**ブラウザでしか確かめられない部分**: IndexedDB は Node に無いので、`openDb` / `idbGet` /
`idbPut` / `ensureKeyPair` の再利用経路はコードレビューによる確認です。実ブラウザでの
鍵の永続化とボタンの有効化も同様です。

`tests/demolog.test.ts` は `src/demolog.ts` 単体のテストです
(`DEMO_LOG=0` での無効化、8 文字切り詰め、色の優先順位、桁揃え、`holds:` / `never:` が
起動行にしか出ないこと)。`tests/rp.test.ts` の `describe("demo log", ...)` では実サーバに
対して `console.log` を spy し、`GET /` で `landing` の 1 行、成功する `POST /callback` で
到着行 + `Ed25519 ✓` の 2 行 (✖ 行なし)、失敗する `POST /callback` で到着行 +
`[rp]      ✖ callback rejected: <理由>` の 1 行 (検証行は出ない) が出ること、
`DEMO_LOG=0` で `[rp]` 出力が消えることを確認します。

加えて `interop with the gateway's JWT and JWKS wire format` では、gateway/SDK が実際に出す
バイト列を再現したトークンを受理することを確認します。gateway のコードは import せず、
参照実装の規則 (`deterministicJsonStringify` によるキーのソート、ヘッダ
`{alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1"}`、`iss`/`sub`/`aud`/`iat`/`exp`/`nonce`/`cnf.jkt`
のペイロード、`{kty, crv, x, kid, use, alg}` の JWKS エントリ、`x` = 生の 32 バイト公開鍵の base64url)
をテスト側で組み立て直しています。

## ソース構成

```
src/
├── index.ts     # 環境変数の読み取りと listen
├── server.ts    # ルーティング (GET /, POST /callback, GET /health)
├── config.ts    # 環境変数 → RpConfig
├── jwks.ts      # JWKS の取得・キャッシュ・kid 選択
├── jwt.ts       # base64url 分解と Ed25519 検証、クレーム検証
├── html.ts      # ページテンプレート + インライン DPoP JS (DPOP_SCRIPT ほか)
└── demolog.ts   # デモログ (第 10 節の圧縮形式で stdout に出力)
```

`createRpServer(config)` は `listen` していない `http.Server` を返すので、テストからポート 0 で起動できます。
