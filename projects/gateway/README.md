# gateway — OAuth プロキシ + OIDC エンドポイント + デモ UI 配信

PASTA 分散 IdP の **フロント**。ブラウザ / クライアント SDK からの要求を受け、FROST の
2 ラウンドを `node` コンテナ群にオーケストレーションし、OIDC の Discovery と JWKS を
公開し、React 製のデモ UI を静的配信します。

`docs/container-split.md` 第 6 節の契約に対応するコンポーネントです。

**このゲートウェイはトークンを持ちません。** ノードから返るのは `h_i` で暗号化された
シェア `ct_i` だけで、gateway はパスワードも `h_i` も `rs_i` も持たないため、これを復号
することも署名を偽造することもできません。平文の ID トークンが組み上がるのは、
パスワードを知っているクライアント側だけです。

**gateway はパスワードを一切受け取りません。** クライアント SDK はブラウザ
(`projects/demo`) で実行され、gateway が受け取るのはブラインド化された点
`A = r·H1(password)` だけです。`r` を知らないので `A` から `h` を導くことはできません。
以前あった `/api/pasta/browser-sign-on` (gateway 内で SDK を実行してトークンを組み立てる
デモ用ショートカット) は **削除しました** (契約 第 11 節)。あのルートは gateway に平文の
パスワードを渡すもので、このアーキテクチャが主張する性質そのものを崩していました。
`/api/pasta/sign-on` のボディに `password` を入れて送っても、gateway は `username` と
`blinded` しか読まないため単に無視されます (ログにも出ません)。

## 起動方法

### ローカル

```bash
npm install
npm test
npm run build

# デモ UI を先にビルドしておく (gateway はビルド済みの成果物を配信するだけ)
cd ../demo && npm ci && npm run build && cd ../gateway

NODE_URLS=http://localhost:4001,http://localhost:4002,http://localhost:4003 \
GROUP_CONFIG=../dealer/sample-output/group.json \
DEMO_DIST=../demo/dist \
npm start
```

`npm run dev` はビルド無しで `tsx` から同じものを起動します。

先に `dealer` が `group.json` を書き、`node` が 3 台起動している必要があります
(`dealer/README.md`, `node/README.md`)。

```bash
curl -s http://localhost:3000/health
```

### Docker

**ビルドコンテキストはリポジトリルート**です。イメージは `projects/demo/` もビルドして
同梱するため、`projects/gateway/` 単体をコンテキストにはできません。

```bash
docker build -f projects/gateway/Dockerfile -t pasta-gateway .

docker run -d --name gateway -p 3000:3000 \
  -e NODE_URLS=http://node1:4001,http://node2:4002,http://node3:4003 \
  -e GROUP_CONFIG=/secrets/group.json \
  -v "$PWD/projects/dealer/sample-output:/secrets:ro" \
  pasta-gateway
```

`node:22-alpine` の 4 ステージ構成 (demo UI ビルド / gateway ビルド / production 依存 /
ランタイム)。ランタイムには `dist/`、production 依存、`/app/ui` のデモ UI だけが入り、
非 root (`node` ユーザー) で起動します。`HEALTHCHECK` は `/health` を叩きます
(alpine に curl が無いため `node -e "fetch(...)"`)。値は契約 第 8 節の標準
`--interval=5s --timeout=3s --start-period=3s --retries=3` です。gateway はノード発見が
終わってから listen するので、起動直後の数回は接続拒否で失敗しますが、5 秒間隔 × 3 回の
猶予に収まります。`/health` がノードを 1 台ずつ叩く際のタイムアウトは 2 秒に絞ってあり、
ノードが 1 台ハングしても gateway 自身の応答が `--timeout=3s` を超えないようにしています。

`SIGTERM` でリスナーを閉じ、処理中の要求を終えてから exit 0 します。

### docker compose

```yaml
gateway:
  build:
    context: .
    dockerfile: projects/gateway/Dockerfile
  ports: ["3000:3000"]
  environment:
    ISSUER: http://localhost:3000          # ブラウザから見える URL = JWT の iss
    NODE_URLS: http://node1:4001,http://node2:4002,http://node3:4003
    GROUP_CONFIG: /secrets/group.json
  volumes:
    - ./secrets:/secrets:ro
  depends_on:
    node1: { condition: service_healthy }
    node2: { condition: service_healthy }
    node3: { condition: service_healthy }
```

## 環境変数

| 変数 | 既定 | 意味 |
|---|---|---|
| `PORT` | `3000` | 待受ポート。整数 (0–65535) 以外は起動時エラー |
| `ISSUER` | `http://localhost:${PORT}` | JWT の `iss`、Discovery の `issuer`。**末尾スラッシュ無し** (付いていても除去する) |
| `NODE_URLS` | `http://localhost:4001,http://localhost:4002,http://localhost:4003` | カンマ区切り。**順序と nodeId は対応しない** (下記「ノード発見」) |
| `THRESHOLD` | `group.json` の `threshold` | quorum。明示すると `group.json` の値を上書きする |
| `GROUP_CONFIG` | `/secrets/group.json` | dealer 出力。`groupPublicKey` (hex 64) と `keyId` を読む |
| `DEMO_DIST` | `/app/ui` | ビルド済みデモ UI のディレクトリ |
| `DEMO_LOG` | `1` | デモログ (下記)。`0` のときだけ無効、それ以外の値は有効 |
| `FORCE_COLOR` | (イメージでは `1`) | デモログの色。`0` で無色。`NO_COLOR` が設定されていれば無条件で無色 |

`group.json` は起動時に一度だけ読みます。読めない・`version` が 1 でない・
`groupPublicKey` が 32 バイト hex でない、といった場合は 1 行だけ説明を出して exit 1
します。ポートを開く前に落ちます。

`keyId` は JWKS の `kid` になります。クライアント SDK (コピー凍結) はトークンヘッダに
`kid: "pasta-group-key-1"` を固定で書き込むため、dealer を `--key-id` で別の値にすると
RP が `kid` で鍵を引けなくなります。値が食い違う場合は起動時に警告を出します。

## ノード発見

`NODE_URLS` は**順不同のリスト**です。gateway は起動時に各 URL の `GET /health` を
叩き、応答の `nodeId` でそのノードの識別子を知ります。compose ファイルに「どの
コンテナがどのシェアを持つか」を書かずに済み、設定ファイルを取り違えて起動した
ノードもここで見つかります。

- `NODE_URLS` の各項目は絶対 URL (`http` / `https`) でなければなりません。綴り間違いは
  再試行しても直らないので、起動直後にその場で落とします。
- まだ起動していないノードは **1 秒間隔で最大 30 回** 再試行します。
- すべての URL が応答するまで待ちます。閾値ぶんだけ揃っても、設定された台数が
  揃わない限り起動しません (壊れた構成が動くデモの裏に隠れないように)。
- 各ノードの `groupPublicKey` を `group.json` と突き合わせます。別の鍵セレモニーの
  ノードは、その場で拒否します (再試行しません)。
- 同じ `nodeId` を名乗る URL が 2 つある場合も起動しません。

起動後にノードが落ちた場合は別扱いです。`/api/pasta/sign-on` と
`/api/pasta/refresh` は、`participants` の指定が無ければ **実際に commit を返した
ノード**で quorum を組みます。3 台中 1 台が落ちていても 2-of-3 で成功し、閾値を
下回ってはじめて 400 になります。`participants` を明示した場合は、指定した全ノードが
応答しなければエラーです (要求された quorum を黙って別のものに置き換えないため)。

## HTTP API

すべて既存モノリスと**同一パス・同一 JSON フィールド名**です。バイト列は
**base64url (パディング無し)**、`Uint8Array` を JSON に直接入れることはありません
(契約 第 3 節)。

| Method | Path | 備考 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/jwks.json` | グループ公開鍵 1 本の JWK Set (RFC 8037, `kty=OKP` / `crv=Ed25519`) |
| GET | `/authorize` | 検証して `/demo?step=login&redirect_uri=...&dpop_jkt=...` へ meta refresh。`dpop_jkt` 必須 |
| POST | `/api/pasta/sign-on` | `ProxySignOnRequestBody` → `ProxySignOnResult` (b64u 化)。`nonce` 必須 |
| POST | `/api/pasta/refresh` | `ProxyRefreshRequestBody` → `ProxyRefreshResult` (b64u 化)。`nonce` 必須 |
| POST | `/demo/rp-callback` | デモ UI の既定 form_post 先。簡易 RP 表示 |
| GET | `/`, `/demo`, `/assets/*` | 静的配信 (`DEMO_DIST` 配下) |
| GET | `/health` | `{ "status", "nodes":[{nodeId,url,healthy}] }` |

`/api/pasta/sign-on` と `/api/pasta/refresh` の応答で base64url になるのは
`commitments[].D` / `.E` と `nodeResponses[].commitment.D` / `.E` です。
`toprfPartial`, `ct_i`, `blinded`, `sessionNonce` は元から base64url 文字列なので
そのまま通ります。

### `nonce` は必須

`/api/pasta/sign-on` と `/api/pasta/refresh` のどちらも、
`nonce` が**非空文字列でなければ 400** です (契約 第 6 節「プロキシ層の規則」)。省略・
`null`・空文字列のいずれも拒否し、ノードには一切送りません。

理由は参照実装の `deterministicJsonStringify` にあります。この関数は `Object.keys` を
走査するため、`nonce: undefined` を持つペイロードを `"nonce":undefined` と書き出します。
これは JSON として不正です。ノードとクライアントは同じバイト列に合意するので FROST 署名
そのものは正しく通り、**署名は検証できるのにクレームが `JSON.parse` できない** ID トークン
が出来上がります。RP がトークンを検証した後になって初めて壊れていることが分かる、という
最悪の壊れ方です。`jwt.ts` はコピー凍結 (契約 第 1 節) で直せないため、gateway の入口で
防ぎます。

### `dpop_jkt` (契約 第 13 節)

`/authorize` は `dpop_jkt` を **必須** とします。値は RP フロントが持つ DPoP 公開鍵の
RFC 7638 サムプリント (SHA-256 の base64url) なので、`^[A-Za-z0-9_-]{43}$` に一致しなければ
なりません。欠落・長さ違い・パディング付き・標準 base64 の英数字は、他のパラメータ不正と
同じ経路で `400 Authorize Error: ...` になります。検証を通った値は `/demo` への引き継ぎ URL に
`&dpop_jkt=<jkt>` として乗り、デモ UI がそれをそのまま `cnfJkt` に使います。

この結果、**gateway もデモ UI もノードも DPoP 秘密鍵を持ちません**。持っているのは rp
オリジンのページだけで、gateway が知るのはサムプリントだけです。

`src/gateway/oidc.ts` は第 13 節から byte 凍結の対象外になりました (OIDC のグルーコードで
あって暗号ではないため)。参照実装 (`ba20f512` の `src/gateway/oidc.ts`) からの差分は次の
2 箇所だけです。

- `validateAuthorizeRequest`: `AuthorizeQueryParams` に `dpop_jkt`、戻り値の `params` に
  `dpopJkt` を追加し、`nonce` の検査の後に必須チェックと 43 文字 base64url の書式検査を足した。
- `renderAuthorizePage`: 引数に `dpopJkt` を追加し、`/demo` の URL の末尾に
  `&dpop_jkt=${encodeURIComponent(params.dpopJkt)}` を足した。DPoP 鍵生成に触れていた
  コメントの手順も現状に合わせた。

Discovery, JWKS, `response_type` / `response_mode` / `scope` / `nonce` の検査、HTML の
組み立て方は参照実装のままです。

### ステータスコード

| Code | いつ |
|---|---|
| 200 | 成功 |
| 204 | `OPTIONS` (CORS プリフライト) |
| 400 | 必須フィールドの欠落 (`nonce` ほか、上記)、`/authorize` のパラメータ不正、プロキシ側の拒否 (未知ユーザー、quorum 不足、無効セッション、DPoP 検証失敗)、ボディが JSON でない、`/demo/rp-callback` の `id_token` 欠落。ボディは `{ "error": message }` |
| 403 | 静的配信でディレクトリ外へ出ようとしたパス |
| 404 | 不明なパス |
| 413 | リクエストボディが 1MB を超えたとき (バイト数で判定) |
| 500 | 想定外。ボディは常に `{ "error": "Internal server error" }` で、パスや内部状態を漏らさない。詳細はログにだけ出る |
| 503 | `/health` で健全なノードが閾値未満のとき (ボディの `status` は `"degraded"`) |

パスワード誤りに gateway は**関与しません**。ノードは全台正常に応答し、gateway は 200 を
返し、ブラウザ側の SDK が `ct_i` を開く段階で AEAD 復号に失敗します。gateway から見ると
成功したサインオンと区別が付きません。

`/demo/rp-callback` が HTML に埋め込む値 (`state`、検証エラー文言、検証済みクレーム)
はすべてエスケープします。`state` は認証なしのフォーム項目で、検証エラー文言は署名を
検証する前の JWT ヘッダ由来なので、いずれも呼び出し側が自由に決められます。この
ページは gateway 自身のオリジン (デモ UI と同じ) で配信されるため、素通しにすると
IdP のオリジンでスクリプトが動くことになります。

### 静的配信

配信するのは `/` と `/demo` (どちらも `index.html`)、および `/assets/...` だけです。
解決後のパスが `DEMO_DIST` の外に出る場合は 403 で拒否します。判定は 2 段階で、
`..` を含むパスは解決後の位置で、`DEMO_DIST` 配下に置かれたシンボリックリンクは
`realpath` の結果で弾きます。

## デモ UI

`projects/demo/` の React アプリを、Dockerfile のステージ 1 で `npm ci && npm run build`
して `/app/ui` に配置します。`projects/demo/` 側のソースは変更していません。

ローカル開発では `cd demo && npm ci && npm run build` の後に
`DEMO_DIST=../demo/dist npm start` としてください。`demo/` 側で `npm run dev`
(Vite, ポート 5173) を使う場合は、Vite の proxy 設定が `/api` などを
`http://localhost:3000` へ転送します。

## デモログ

契約 第 10 節の圧縮形式 (1 イベント = 1〜2 行、英語) で、gateway が**何を受け取り、
何を中継し、何を構造的に持ち得ないか**を stdout に出します。node (青) / rp (緑) /
ブラウザ (黄) のログと並べて眺めることで、「ブラウザ以外は id_token を組み立てる材料を
揃えられない」ことが見えます。gateway の色は**マゼンタ**です。

イベント名は専用の桁に左詰めし、2 行目はその桁ぶん字下げするので、4 列を並べたときに
縦が揃います。値は base64url の先頭 8 文字 (`…` は付けません)。長期秘密は切り詰めても
出しませんが、そもそも gateway は 1 つも持っていません。

```
[gateway] ● up      t=2/3 nodes=3 issuer=http://localhost:3000   holds: group pubkey, kid=pasta-group-key-1   never: s_i, k_i, h_i, pw, id_token
[gateway] authorize client_id=demo_client nonce=compact-6 state=compact-6-state dpop_jkt=Rupx_EC1  → redirect /demo
[gateway] sign-on   sess=8fa90b5e round=ef54f65f user=alice nonce=compact-1  ← A mNDkmKAj  jkt y7VfmjvC  (no pw)
                    round1 (D,E)×3 → round2 ← B_i×3 ct_i×3 (no h_i, cannot decrypt) → relayed as-is
[gateway] refresh   sess=8fa90b5e round=8837fc27  ← DPoP eyJhbGci (verified by nodes)  → ct_i×3 relayed
[gateway] jwks      public only
[gateway] discovery public only
```

出るイベント:

| イベント | 行 |
|---|---|
| 起動 | `● up t= nodes= issuer=` + `holds:` / `never:` (1 行) |
| `GET /authorize` | `authorize client_id= nonce= state= dpop_jkt= → redirect /demo` (1 行)。`dpop_jkt` は暗号学的な値なので先頭 8 文字 |
| `POST /api/pasta/sign-on` | `sign-on sess= round= user= nonce= ← …` + 中継の内訳 (2 行) |
| `POST /api/pasta/refresh` | `refresh sess= round= ← DPoP … → ct_i×N relayed` (1 行) |
| `POST /demo/rp-callback` | `rp-demo ← id_token … → Ed25519 ✓` (1 行) |
| `GET /jwks.json` | `jwks public only` (1 行) |
| `GET /.well-known/openid-configuration` | `discovery public only` (1 行) |
| 拒否 | `✖ <event> rejected: <reason>` (1 行) |

`never:` は起動行にだけ出します。以後のイベントで繰り返さないのは、列を見比べれば
起動行で分かるからです。

ノードが 1 台落ちて quorum を組み直したときは、2 行目が
`round1 (D,E)×2 (node3 unreachable, excluded) → round2 …` になります。閾値を割った
ときの拒否行は `✖ sign-on rejected: quorum 1 < 2 (node2, node3 unreachable)` です
(クライアントに返る HTTP のメッセージは従来どおりで、この短縮形はログだけの表現)。
除外の判断を持っているのは `proxy.ts` なので、サインオンとリフレッシュのイベントは
ルートハンドラではなくそこから、2 ラウンドが終わった時点でまとめて書き出します
(並行リクエストどうしで行が混ざらないように)。

`password` はここに出しようがありません。gateway は受け取らず、`src/demolog.ts` の
イベント型はどれも `password?: never` を宣言しているため、渡そうとするとコンパイルが
通りません。

環境変数:

- `DEMO_LOG=0` で無効 (それ以外の値は有効)。既存の運用ログ (`listening on …`、エラー)
  は残ります。
- 色は `NO_COLOR` → `FORCE_COLOR=0` → `FORCE_COLOR` (0 以外) → TTY 判定 の優先順位。
  イメージは `FORCE_COLOR=1` を既定にしています (`docker compose logs` は TTY でない
  ため)。デモで色を消すときは `NO_COLOR` ではなく `FORCE_COLOR=0` を使ってください
  (`NO_COLOR` は Node 本体が警告を出します)。

```bash
docker compose logs -f --no-log-prefix gateway
```

## テスト

```bash
npm test
```

- `tests/dpop_and_oidc.test.ts` — モノリスの `tests/gateway_and_dpop.test.ts`
  (コミット `ba20f512`。現行リポジトリからは削除済み) から
  移植した DPoP (RFC 9449) / `cnf.jkt` / form_post / OIDC の単体テスト。
- `tests/static.test.ts` — 静的配信のパス解決。クライアントが正規化してしまって
  HTTP 越しには届かないディレクトリトラバーサルを直接検証する。
- `tests/e2e.test.ts` — フィクスチャ 3 ノード分の**フェイクノード HTTP サーバ**を
  ポート 0 で 3 つ、gateway もポート 0 で起動し、すべて実ソケット越しに検証する。
  ノード発見、JWKS、クライアント SDK の HTTP モードでのサインオンと JWKS 検証、
  リフレッシュ、URL 2 つだけの構成、起動後にノードが落ちた場合の quorum 再編成、
  閾値割れでの失敗、`nonce` 欠落 / `null` / 空文字列の 400、削除した
  `browser-sign-on` が 404 であること、ボディの `password` が無視され `username` と
  `blinded` だけが使われること、誤パスワードが SDK 側の復号失敗になること、
  組み上がったトークンのクレームが `JSON.parse` できること、デモログの 2 行構造と
  ノード除外と拒否行、`/authorize`、`/demo/rp-callback`、`/health`、静的配信と
  トラバーサル拒否。
- `tests/demolog.test.ts` — デモログ単体。`DEMO_LOG` による無効化、色の優先順位、
  8 文字切り詰め、各イベントの文言 (`never:` が起動行にしか出ないこと、桁揃え)。

フェイクノードは `tests/helpers/protocol/node.ts` (モノリスの
`src/protocol/node.ts`（コミット `ba20f512`。現行リポジトリからは削除済み）の
byte 一致コピー) を第 5 節の HTTP API で包んだものです。
リクエストの検証は `node/src/wire.ts` と同じ厳しさにしてあります (寛容なスタブが
gateway 側のバグを覆い隠さないように)。
`node/` プロジェクトからは何も import していません。`tests/fixtures/` は
`projects/dealer/sample-output/` のコピーです。

## ここに無いもの

鍵生成 (それは `dealer`)、シェアの保持と署名 (それは `node`)、RP の
ランディングと `form_post` 受信 (それは `rp`)。`/rp` と `/rp/callback` は
モノリスから引き継いでいません。
