# コンテナ分割 設計契約 (container-split)

このリポジトリを「エンティティ (docker コンテナ) 単位の完全独立プロジェクト」に分割するための契約文書。
各コンポーネントの実装エージェントとレビューエージェントは **この文書を唯一の共通仕様** として作業する。
この文書に無い判断は、既存実装 (`src/`, `tests/`) の振る舞いを保つ方向で行う。

## 0. 決定事項 (変更不可)

| 論点 | 決定 |
|---|---|
| リポジトリ構成 | 完全独立プロジェクト。共有ライブラリは作らない。必要なコードは各ディレクトリに **コピー** する |
| 鍵配布 | `dealer` CLI が起動前に一度だけ実行され、ノード毎の JSON を `secrets/` に書き出す。DKG はスコープ外 (trusted dealer) |
| ユーザー登録 | dealer が alice / bob を事前登録し、レコードをノード JSON に含める。登録 API は作らない |
| デモ UI | `gateway` に同梱 (gateway イメージが `projects/demo/` をビルドして静的配信) |
| `/api/pasta/browser-sign-on` | ~~現状維持~~ → **廃止** (2026-09-06 改定、第 11 節)。クライアント SDK はブラウザで実行し、gateway はパスワードを受け取らない |
| デモログ | 全コンポーネントが「受信 / 計算 / 非保持」の統一形式で stdout に出す (第 10 節)。並列表示は tmux (第 12 節) |
| 既存 `src/`, `tests/` | 削除済み。参照実装はコミット `ba20f512` の `src/`, `tests/` |

## 1. ディレクトリ構成

```
beaver-triple-mpc/
├── docker-compose.yml        # 最終ステップで作成
├── secrets/                  # dealer の出力先 (gitignore 済み)
├── projects/
│   ├── dealer/                # 鍵シェア・ユーザーレコード生成 CLI (one-shot コンテナ)
│   ├── node/                  # IdentityNode HTTP サーバ (同一イメージを node1..3 として起動)
│   ├── gateway/                # OAuth プロキシ + OIDC エンドポイント + デモ UI 配信
│   ├── rp/                    # ZK-App Portal (Relying Party)
│   └── demo/                  # 既存 React UI ソース (gateway がビルド時にコピーして使う)
└── docs/container-split.md   # 本文書
```

本文中の `src/` への参照はコミット `ba20f512` 時点のファイルを指す（現行リポジトリには存在しない）。

### 各プロジェクトの共通ルール

- 各ディレクトリは **単独で** `npm ci && npm test && docker build .` が成功する。
- `../` を跨ぐ import、`src/` への依存、他コンポーネントディレクトリへの参照は **禁止**。テストフィクスチャも自ディレクトリ内にコピーする。
- 構成: `package.json` (`"type": "module"`), `tsconfig.json` (ルートのものと同じ設定、`strict: true`), `vitest.config.ts`, `Dockerfile`, `.dockerignore`, `README.md`, `src/`, `tests/`。
- 依存はルート `package.json` と同じもの・同じバージョン範囲から **実際に使うものだけ** を選ぶ (`@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `typescript`, `vitest`, `tsx`, `@types/node`)。未使用の依存を残さない。新規ランタイム依存の追加は不可。HTTP は `node:http` と `fetch` で実装する。
- Docker: `node:22-alpine` のマルチステージビルド。ランタイムステージには `dist/` と production 依存のみ。非 root ユーザーで起動。常駐サービスは `HEALTHCHECK` を定義する (one-shot の dealer は不要)。
- コピーしたコードは **暗号ロジックを一切変更しない**。コピーは **ファイル単位で原文と byte 一致** させる (`diff` が無出力)。コピー元ファイル内に自コンポーネントで使わない export が含まれていてもそのまま残す (部分削除やインポート整理をしない)。使わないファイルはコピーしない。変更が必要になった場合は作業を止めて報告する。
- git commit はしない (オーケストレーター側で行う)。

## 2. ポート・ホスト名

| サービス | compose 内ホスト名 | コンテナ内ポート | ホスト公開ポート | ブラウザから見える URL |
|---|---|---|---|---|
| node1 | `node1` | 4001 | 4001 | (公開不要、デバッグ用) |
| node2 | `node2` | 4002 | 4002 | 同上 |
| node3 | `node3` | 4003 | 4003 | 同上 |
| gateway | `gateway` | 3000 | 3000 | `http://localhost:3000` |
| rp | `rp` | 3001 | 3001 | `http://localhost:3001` |

- JWT の `iss` は **ブラウザから見える URL** (`http://localhost:3000`) とする。RP の `iss` 検証もこの値と比較する。`ISSUER` 系の URL 環境変数は **末尾スラッシュ無し** で指定する (rp 側は末尾スラッシュの有無だけは無視して比較する)。
- RP がサーバ側で JWKS を取得するときは compose 内 URL (`http://gateway:3000`) を使う。

## 3. エンコーディング規約

- **secrets ファイル (dealer 出力)**: バイト列・スカラーは **小文字 hex** 文字列。スカラー (bigint) は 64 桁 hex (32 バイト、**big-endian**、ゼロ埋め)。読み込み側は `BigInt("0x" + hex)` で復元する。既存 `frost.ts` の `scalarToBytes` は little-endian なので、hex 変換にそれを経由してはならない。
- **HTTP ワイヤ (全サービス)**: バイト列は **base64url (パディング無し)**。JSON に `Uint8Array` をそのまま入れてはならない (既存 `PastaOAuthProxy` の戻り値 `commitments[].D/E` は Uint8Array のため、gateway の HTTP 応答では必ず base64url に変換する)。
- base64url の実装は既存 `src/jwt/jwt.ts` の `base64UrlEncode` / `base64UrlDecode` をコピーして使う。

## 4. dealer

### 責務

1. FROST 用マスター秘密を生成し、Shamir (t=2, n=3) で分割してグループ公開鍵を得る (`src/crypto/frost.ts` の `generateShamirShares`, `randomScalar`)。
2. ユーザー alice (`password123`, sub `usr_alice_12345`) と bob (`password456`, sub `usr_bob_67890`) について、既存 `registerUserToNodes` と同じ計算 (TOPRF 鍵分割、`h` 導出、`deriveServerKey(h, nodeId)`) を行い、ノード毎の `UserRecord` を作る。パスワードはファイルに **書かない**。
3. 以下のファイルを出力ディレクトリに書く。

### CLI

```
node dist/index.js --out <dir> [--threshold 2] [--total 3] [--key-id pasta-group-key-1]
```

`--key-id` は **`pasta-group-key-1` から変更しないこと** (gateway に凍結コピーされたクライアント SDK が JWT ヘッダの `kid` にこの値を固定で書き込むため。変更すると rp が JWKS から鍵を引けない)。ユーザー一覧は `--users alice:password123:usr_alice_12345,bob:password456:usr_bob_67890` で上書き可能。既定値は上記 2 名。出力先に既にファイルがあれば上書きせず exit 1 (`--force` で上書き)。`--if-missing` を指定すると、出力ファイル一式が既に揃っている場合は何も書かず exit 0 で終了する (compose の再起動で鍵が変わらないようにするため)。 一式のうち一部だけ存在する場合は通常の存在チェックに従い exit 1 (`--force` があれば全体を上書き)。

### 出力ファイル形式

`<out>/group.json` (gateway が読む。rp は JWKS 経由で鍵を得るので読まない):

```json
{
  "version": 1,
  "threshold": 2,
  "total": 3,
  "keyId": "pasta-group-key-1",
  "groupPublicKey": "<hex 64>"
}
```

`<out>/node-<id>.json` (id = 1..total、各ノードが読む):

```json
{
  "version": 1,
  "nodeId": 1,
  "threshold": 2,
  "total": 3,
  "groupPublicKey": "<hex 64>",
  "secretKeyShare": "<hex 64>",
  "users": [
    {
      "username": "alice",
      "sub": "usr_alice_12345",
      "toprfKeyShare": { "id": 1, "value": "<hex 64>" },
      "h_i": "<hex 64>"
    }
  ]
}
```

### 完了条件

- テスト: 出力 3 ノード分の `secretKeyShare` から任意 2 つで再構成した秘密のグループ公開鍵が `group.json` と一致する。出力 `toprfKeyShare` 任意 2 つと alice のパスワードから `h` を再計算し、`deriveServerKey(h, i)` が各 `h_i` に一致する。
- `projects/dealer/sample-output/` に生成物一式をコミット用に置く (node / gateway のテストフィクスチャ元)。
- `docker build` 後、`docker run --rm -v $(pwd)/out:/out <image> --out /out` でファイルが生成される。

## 5. node

### 責務

既存 `src/protocol/node.ts` の `IdentityNode` を **そのままコピー** し、薄い HTTP アダプタで包む。起動時に `NODE_CONFIG` の JSON を読み、`IdentityNode` を構築し、`users` を `registerUser` で登録する。

### 環境変数

| 変数 | 既定 | 意味 |
|---|---|---|
| `NODE_CONFIG` | `/secrets/node.json` | dealer 出力の `node-<id>.json` のパス |
| `PORT` | `4000` | 待受ポート |

### HTTP API (gateway → node)

すべて `Content-Type: application/json`。バイト列は base64url。

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/health` | - | `{ "status": "ok", "nodeId": 1, "groupPublicKey": "<b64u>" }` |
| POST | `/commit` | `{ "roundId": string }` | `{ "nodeId": 1, "D": "<b64u>", "E": "<b64u>" }` |
| POST | `/sign-on` | `{ "roundId": string, "request": SignOnRequestWire }` | `SignOnResponseWire` |
| POST | `/refresh` | `{ "roundId": string, "request": RefreshRequestWire }` | `RefreshResponseWire` |

- `SignOnRequestWire` = 既存 `SignOnRequest` と同じフィールド。ただし `commitments: [{ nodeId, D: b64u, E: b64u }]`。
- `SignOnResponseWire` = 既存 `SignOnResponse` と同じフィールド。`commitment: { D: b64u, E: b64u }`。
- `RefreshRequestWire` / `RefreshResponseWire` も同様に既存型のバイト列フィールドを base64url にしたもの。
- ノードは `/sign-on`, `/refresh` で受けた `roundId` に対応する自分の nonce を使う (既存 `handleSignOn(roundId, req, commitment)` の第 3 引数は、`/commit` で自分が返した値をリクエスト内 `commitments` から自ノード id で引いて渡す)。
- エラー: `IdentityNode` が throw した場合およびリクエスト形式不正は `400 { "error": message }`。ルート不明 404、メソッド不一致 405、ボディ 1MB 超過 413、その他 500。**非 200 応答のボディはすべて `{ "error": string }`** とする。`nonce` は省略 (キー無し) または文字列のみ受け付け、`null` は 400。

### 完了条件

- ユニット: 既存 `tests/pasta_integration.test.ts` のうちノード単体で成立するもの (nonce 単回使用、AAD 束縛、sub はサーバ記録から) をコピーして通す。
- コンポーネント e2e: vitest 内で実サーバをポート 0 で起動し、`projects/dealer/sample-output` からコピーしたフィクスチャ 3 ノード分を **3 プロセス相当 (3 インスタンス)** で立て、HTTP 経由で `/commit` → `/sign-on` を行い、テスト側 (コピーしたクライアント SDK 相当のコード) で復号・集約した JWT が `groupPublicKey` で Ed25519 検証できること。誤パスワードで復号に失敗すること。
- Docker: `docker run -e NODE_CONFIG=/secrets/node-1.json -v .../sample-output:/secrets:ro -p 4001:4001 -e PORT=4001 <image>` で `/health` が 200。

## 6. gateway

### 責務

既存 `src/bin/gateway.ts` から **RP 関連 (`/rp`, `/rp/callback`) を除いた** 全ルートを引き継ぐ。ノードはメモリ上のオブジェクトではなく、`NODE_URLS` の HTTP エンドポイントとして扱う。

- `PastaOAuthProxy` をコピーし、`IdentityNode` 直接呼び出しを **`NodeClient` インターフェース** 経由に置き換える。`HttpNodeClient` が第 5 節の API を叩く。テスト用に同一インターフェースのインプロセス実装 (コピーした `IdentityNode` を包む) を `tests/` に置いてよい。
- `/api/pasta/browser-sign-on` は **廃止** (第 11 節)。gateway はクライアント SDK を実行せず、パスワードを受け取らない。gateway 内の `client-sdk/client.ts` コピーはテスト (HTTP モードでの e2e) でのみ使う。`client-sdk/client.ts` のコピーは **byte 一致の例外** とし、`proxyUrl` (HTTP) 分岐で応答を Wire 形式からデコードする変更のみ許容する (参照実装の HTTP 分岐は Uint8Array を JSON から復元できず機能していなかった)。`proxy.ts` と `session.ts` も NodeClient 化に伴う変更を許容する (変更を伴う移植)。
- デモ UI: Dockerfile のビルドステージで `projects/demo/` (ビルドコンテキストはリポジトリルート、`projects/gateway/Dockerfile` を `-f` 指定) をビルドし、`/`, `/demo`, `/assets/*` で配信。`/demo/rp-callback` も現状維持。

### 環境変数

| 変数 | 既定 | 意味 |
|---|---|---|
| `PORT` | `3000` | 待受 |
| `ISSUER` | `http://localhost:3000` | JWT `iss`、Discovery の `issuer` |
| `NODE_URLS` | `http://localhost:4001,http://localhost:4002,http://localhost:4003` | カンマ区切り。順に nodeId 1,2,3 と対応させず、起動時に各 `/health` を叩いて `nodeId` を取得する |
| `THRESHOLD` | `group.json` の `threshold` | quorum。環境変数があれば上書き |
| `GROUP_CONFIG` | `/secrets/group.json` | dealer 出力 |
| `DEMO_DIST` | `/app/ui` | ビルド済みデモ UI のパス |

### 外部 HTTP API (ブラウザ / SDK → gateway)

既存と **同一パス・同一 JSON フィールド名**。バイト列は base64url (第 3 節)。

| Method | Path | 備考 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | 既存 `OidcEndpointHandler` |
| GET | `/jwks.json` | 同上 |
| GET | `/authorize` | 既存通り検証して `/demo?step=login&redirect_uri=...` へ。`dpop_jkt` は必須 (`^[A-Za-z0-9_-]{43}$`、欠落・不正は 400) で、`/demo` の URL にそのまま引き継ぐ (第 13 節) |
| POST | `/api/pasta/sign-on` | `ProxySignOnRequestBody` → `ProxySignOnResult` (b64u 化) |
| POST | `/api/pasta/refresh` | `ProxyRefreshRequestBody` → `ProxyRefreshResult` (b64u 化) |
| POST | `/demo/rp-callback` | 既存の簡易 RP 表示 (デモ UI の既定ターゲット) |
| GET | `/`, `/demo`, `/assets/*` | 静的配信 |
| GET | `/health` | `{ "status":"ok", "nodes":[{nodeId,url,healthy}] }` (新設)。健全ノードが閾値以上なら 200、未満なら 503 で `status: "degraded"` |

プロキシ層の規則:
- **`nonce` は必須** (`/api/pasta/sign-on`, `/api/pasta/refresh` で非空文字列を要求し、欠落は 400)。参照実装の `deterministicJsonStringify` は `nonce` が undefined のとき `"nonce":undefined` という不正 JSON をペイロードに書き出すバグがあり、`jwt.ts` はコピー凍結のため gateway 入口で防ぐ。
- ノード呼び出しの失敗や quorum 不足など、プロキシ層で発生したエラーは `400 { "error" }`。予期しない例外は 500。
- `participants` 未指定のサインオンでは、ラウンド 1 (`/commit`) で到達できなかったノードを除外し、残りが閾値以上なら続行する。`participants` 明示時は指定ノード全ての応答を要求する。ラウンド 2 は全か無か (コミットメント集合で R が確定するため)。
- リフレッシュは **サインオン時の参加ノード集合** に対して行う (そのセッションの `rs_i` を持つのは署名したノードだけ)。gateway はセッションごとに参加ノードを記録し、`participants` 未指定のリフレッシュではそのうち到達できるノードで閾値以上を組む。
- 起動時のノード発見は `NODE_URLS` の全 URL が `/health` に応答するまでリトライし、リトライ上限に達したら起動失敗とする (compose では各ノードの healthy を待ってから起動するため、未応答は構成ミスとして扱う)。全ノードの `groupPublicKey` が `group.json` と一致することを検証する。

### 完了条件

- ユニット: 既存 `tests/gateway_and_dpop.test.ts` の DPoP / form_post / OIDC 部分をコピーして通す。
- コンポーネント e2e: vitest 内でフィクスチャ 3 ノード分の **フェイクノード HTTP サーバ** (第 5 節の API を、コピーした `IdentityNode` で実装) をポート 0 で 3 つ起動し、gateway サーバもポート 0 で起動。HTTP 経由で `/api/pasta/sign-on` → クライアント SDK (HTTP モード) で JWT 組み立て → `/jwks.json` の鍵で検証、続けて `/api/pasta/refresh` が成功すること。ノード 1 台を止めても (URL 2 つだけでも) 2-of-3 で成功すること。誤パスワードでは SDK 側の復号が失敗すること。
- Docker: リポジトリルートをコンテキストに `docker build -f projects/gateway/Dockerfile .` が成功し、`/health`, `/demo`, `/.well-known/openid-configuration` が 200。

## 7. rp

### 責務

既存 `src/bin/gateway.ts` の `/rp` (ランディング) と `/rp/callback` (form_post 受信・検証・表示) を独立サービスにする。**署名検証は gateway の JWKS から取得した公開鍵で行う** (group.json を読まない)。JWT の解析と Ed25519 検証は `node:crypto` (`crypto.verify(null, data, { key: jwk, format: "jwk" }, sig)`) で行い、IdP 実装のコードを共有しないことを示す。

### 環境変数

| 変数 | 既定 | 意味 |
|---|---|---|
| `PORT` | `3001` | 待受 |
| `RP_BASE_URL` | `http://localhost:3001` | `redirect_uri` の組み立てに使う |
| `ISSUER` | `http://localhost:3000` | `/authorize` の組み立てと `iss` 検証 |
| `IDP_INTERNAL_URL` | 未設定なら `ISSUER` | JWKS 取得先 (compose では `http://gateway:3000`) |
| `CLIENT_ID` | `demo_client` | `aud` 検証 |

### HTTP

| Method | Path | 備考 |
|---|---|---|
| GET | `/` | 既存 `/rp` の HTML。`redirect_uri` は `${RP_BASE_URL}/callback`。インライン JS が WebCrypto Ed25519 の DPoP 鍵を IndexedDB (`pasta-rp`/`dpop`) に用意し、jkt を画面に出してログインリンクに `&dpop_jkt=<jkt>` を付ける (第 13 節) |
| POST | `/callback` | 既存 `/rp/callback` の HTML。`iss`, `aud`, `exp`, 署名を検証。`kid` で JWKS から鍵を選ぶ。JWKS は起動時ではなく初回要求時に取得しキャッシュ (未知 `kid` で再取得)。サーバはトークンの `cnf.jkt` を表示し、インライン JS が IndexedDB の鍵から再計算した jkt との一致を ✓/✖ で示す (鍵はサーバに送らない、第 13 節) |
| GET | `/health` | `{ "status": "ok" }` |

ステータスコード: 検証成功 200、署名・`iss`・`aud`・`exp`・未知 `kid`・`alg` 不正など検証失敗 401 (失敗 HTML)、`id_token` 欠落 400、リクエストボディ 1MB 超過 413、JWKS 取得不能 502。JWKS 取得失敗はキャッシュせず次回要求で再試行する。未知 `kid` での再取得は、キャッシュ済み文書に対してのみ 1 回行う (取得直後の文書に無い `kid` はそのまま 401)。`iat`/`nbf` は 60 秒のクロックスキューを許容する。未知 `kid` による再取得にレート制限は設けない (デモ範囲)。`nonce` と `state` は表示のみで照合しない (参照実装に合わせたデモとしての意図的な省略。gateway 側にもサーバ照合が無い)。HTML に埋め込むトークン由来の値はすべてエスケープする。

### 完了条件

- コンポーネント e2e: vitest 内でフェイク JWKS サーバ (テストが `node:crypto` で作った Ed25519 鍵) と rp をポート 0 で起動し、正しい JWT で成功表示、改竄 / `iss` 不一致 / 期限切れ / 未知 `kid` で失敗表示になること。
- Docker: `docker build projects/rp/` 成功、`/health` と `/` が 200。

## 8. docker-compose (最終ステップ)

- 起動前に `mkdir -p secrets` を行う (bind mount 先が無いと Docker が root 所有で作成し、uid 1000 の dealer が書けない環境がある)。
- `dealer`: `command: ["--out", "/secrets", "--if-missing"]` (Dockerfile の ENTRYPOINT が `node /app/dist/index.js` のため exec 形式)、`./secrets:/secrets` をマウント。`restart: "no"`。鍵を作り直したいときは `docker compose down && rm -rf secrets/` してから `up`。
- `node1..3`: 同一 `image: pasta-node` を指定して 1 回だけビルドする。`depends_on: dealer: condition: service_completed_successfully`、`./secrets:/secrets:ro`、`NODE_CONFIG=/secrets/node-N.json`、`PORT=400N`。healthcheck は `/health`。
- `gateway`: `depends_on` 各ノード `service_healthy`。`NODE_URLS=http://node1:4001,http://node2:4002,http://node3:4003`。
- `rp`: `depends_on: gateway: service_healthy`。`IDP_INTERNAL_URL=http://gateway:3000`。
- 常駐サービスの `HEALTHCHECK` は `--interval=5s --timeout=3s --start-period=3s --retries=3` を **必須** とする (Docker 24 系は `--start-interval` 未対応。`depends_on: service_healthy` の待ち時間はスタック内で最も遅いサービスに律速される)。
- 総合テスト `scripts/integration-test.sh`: `docker compose up -d --build --wait` 後に、discovery / JWKS 取得、CLI スタンドイン (第 11 節、`projects/demo/cli/sign-on.ts`) で alice の `id_token` 取得、`node:crypto` による外部検証、rp `/callback` への form_post で成功 HTML、`docker compose stop node3` 後にサインオンが依然成功、`stop node2` 後は失敗、を確認する。
- 総合テストは冒頭で `node` (**20 以上**) と `npm` の存在を確認し、`projects/demo/node_modules` が無ければ `npm ci --prefix projects/demo` を実行する。ブラウザ役 CLI がブラウザと同じ SDK を Node で走らせるため。
- 総合テストにデモログ (第 10 節) の検証ステップを置く。固有 nonce でサインオンした後、`docker compose logs --no-log-prefix <svc>` から ANSI を除去して、(a) gateway に `▶ sign-on` 見出しと `受信:`/`計算:`/`非保持:` の 3 行が nonce 付きで出ている、(b) node1..3 に gateway と同じ session id の `▶ sign-on` が出ている、(c) rp に `▶ callback` と `検証 OK` が出ている、(d) 全サービスのログに `password123` が 0 件、(e) `secrets/node-1.json` の `secretKeyShare` の先頭 16 文字がどのログにも無い、(f) node3 停止時に gateway ログへ `到達不能のため除外` が出る、を確認する。
- 並列表示スクリプトは `scripts/demo-tmux.sh` (第 12 節)。

## 9. レビュー観点 (各コンポーネント 3 ラウンド)

各ラウンドは新規エージェントが以下を確認し、見つけた問題を **修正してテストを通した上で** 報告する。

1. **契約適合**: 本文書の API・ファイル形式・環境変数・ポートと実装が一致するか。フィールド名の綴り、base64url/hex の使い分け。
2. **過不足**: 責務表にある機能がすべて実装されているか。責務外のもの (他コンポーネントの役割、未使用コード、コピーしたが使っていないファイル) が混入していないか。ただしコピーしたファイル内の未使用 export は許容 (第 1 節)。
3. **独立性**: `../` import、`src/` 参照、他ディレクトリ参照が無いか。`npm ci` を空の `node_modules` から実行して通るか。
4. **暗号ロジック不変**: コピーされた暗号・プロトコルコードが元 (`src/`) と diff 無しか (`diff -r` で確認)。
5. **テストの実質**: e2e テストが実際に HTTP を経由しているか。失敗ケースが本当に失敗を検証しているか。
6. **Docker**: `.dockerignore` で `node_modules`, `tests` を除外、非 root、`HEALTHCHECK`、イメージが実際に起動して `/health` が返るか。
7. **README**: 起動方法、環境変数、API が本文書と矛盾なく書かれているか。

## 10. デモログ (各コンポーネントが何を知っているかの可視化)

デモでは、各コンポーネントのログをターミナルに並べて表示し、「ユーザー (ブラウザ) 以外は
トークンを組み立てる材料を揃えられない」ことを示す。読者は FROST / TOPRF の基本を知っている前提。
**説明の括弧書きは書かない**。式と値だけを出す。言語は **英語**。

### 形式 (2026-09-06 改定: 圧縮版)

- 1 イベント = 1〜2 行。接頭辞 `[<component>]` の直後にイベント名 (8 文字幅に左詰め)、続けて
  `key=value` の識別子、そのあと `←` (received) / `→` (computed or returned) で区切った内容。
  2 行目以降は接頭辞を繰り返さず、接頭辞 + イベント名幅ぶん (20 桁) の固定インデントにする (1 行目の識別子は可変長なので矢印の列には揃えない)。
- 起動時に 1 行だけ `● up` を出し、そこに `holds:` と `never:` を書く。**以後のイベントでは
  never を繰り返さない** (列を見比べれば起動行で分かる)。
- 値: 暗号学的なバイト列 (A, B_i, ct_i, D, E, R, sessionNonce, jkt, id_token, DPoP proof, r, z_i) は
  base64url/hex の先頭 8 文字 (`…` を付けない)。長期秘密 (`s_i`, `k_i`, `h_i`, `h`, password) は
  切り詰めても出さない。`sess=`, `round=` の id は先頭 8 文字。OIDC の `nonce`, `state`, `user`,
  `sub` は切り詰めない。
- 拒否・失敗は `[<component>] ✖ <event> rejected: <reason>` の 1 行 (ブラウザは `failed:`)。
- 色: `NO_COLOR` → 無色、`FORCE_COLOR=0` → 無色、`FORCE_COLOR` (0 以外) → 有色、それ以外は TTY 判定。
  node = 青系 (nodeId で濃淡)、gateway = マゼンタ、rp = 緑、browser/CLI = 黄。イメージは `ENV FORCE_COLOR=1`。
- `DEMO_LOG` (既定 `1`) で有効、`0` のときだけ無効。運用ログ (`listening on …`) は残す。

### 各列の出力 (サインオン 1 回 + リフレッシュ 1 回の完全な例)

```
[node1]   ● up      id=1 t=2/3 users=alice,bob   holds: s_1, k_1, h_1(alice,bob)   never: pw, h, other s_i/k_i, id_token
[node1]   commit    round=e6a353c2  → D_1,E_1 HKdMb_xA Vm4-KzCO
[node1]   sign-on   sess=d61a8b11 round=e6a353c2 user=alice  ← A eMKDHfR7  (D,E)×3  nonce_s 9UAuty0I  jkt Rupx_EC1
                    → B_1=k_1·A JHfGdi0M  ct_1=AEAD_h1(z_1‖rs_1) 4C1byUwU
[node1]   commit    round=7901638a  → D_1,E_1 M-5WAJT3 YAeh3NfB
[node1]   refresh   sess=d61a8b11 round=7901638a ctr=1  ← DPoP ✓  (D,E)×3  → ct_1=AEAD_rk1(z_1) fNSe5V9x
[node1]   ✖ sign-on rejected: commitments contains no entry for node 1

[gateway] ● up      t=2/3 nodes=3 issuer=http://localhost:3000   holds: group pubkey, kid   never: s_i, k_i, h_i, pw, id_token
[gateway] authorize client_id=demo_client nonce=fmt-1 state=rp-demo  → redirect /demo
[gateway] sign-on   sess=d61a8b11 round=e6a353c2 user=alice nonce=fmt-1  ← A eMKDHfR7  jkt Rupx_EC1  (no pw)
[gateway]           round1 (D,E)×3 → round2 ← B_i×3 ct_i×3 (no h_i, cannot decrypt) → relayed as-is
[gateway] refresh   sess=d61a8b11 round=7901638a  ← DPoP eyJhbGci (verified by nodes)  → ct_i×3 relayed
[gateway] jwks      public only
[gateway] discovery public only
[gateway] rp-demo   ← id_token eyJhbGci  → Ed25519 ✓  (demo-only callback page)
[gateway] ✖ sign-on rejected: quorum 1 < 2 (node2, node3 unreachable)

[rp]      ● up      issuer=http://localhost:3000   holds: JWKS(kid) only   never: pw, A, B_i, ct_i, any node traffic
[rp]      landing   nonce=NcRe02V2abc state=O4QDuujD0Av6  → authorize URL
[rp]      callback  state=fmt-1  ← id_token eyJhbGci (direct from browser, not via gateway)
[rp]                JWKS kid=pasta-group-key-1 → Ed25519 ✓  iss ✓  aud ✓  exp 3598s  sub=usr_alice_12345
[rp]      ✖ callback rejected: Ed25519 signature verification failed

[browser] sign-on   user=alice nonce=fmt-1  → r 02cd2de7  A=r·H1(pw) eMKDHfR7  jkt Rupx_EC1  nonce_s 9UAuty0I
[browser]           ← B_i×3 ct_i×3 (D,E)×3  sess=d61a8b11
[browser]           → h=finalize(pw, unblind(r,B_i))  h_i×3  z_i=dec(ct_i)×3 02fdc3de 001093ed 0484975e  R YXL7yUTj  σ=Σz_i  id_token eyJhbGci ✔ assembled only here
[browser] refresh   sess=d61a8b11 ctr=1  → DPoP proof  ← ct_i×3 (D,E)×3  → rk_i=HKDF(rs_i,ctr)×3  z_i×3  R NfKaZRmG  σ  new id_token eyJhbGci ✔
[browser] ✖ sign-on failed: ct_1 decrypt failed → wrong password (nodes cannot tell)
```

- gateway で到達不能ノードを除外した場合は round1 の直後に `(D,E)×2 (node3 unreachable, excluded)` と書く。
- ブラウザの「応答」と「集約」は 1 イベント (`sign-on` の 2〜3 行目) に統合する。
- rp の `landing` の nonce/state は自分が発行する値なので切り詰めない。
- node の `commit` は 1 行。`refresh` は 1 行に収まるなら 1 行。

## 11. クライアント SDK のブラウザ移行 (gateway からの browser-sign-on 廃止)

決定 (2026-09-06): 第 0 節の「`/api/pasta/browser-sign-on` 現状維持」を撤回し、SDK をブラウザ側で
実行する。gateway はパスワードを一切受け取らない。

- `projects/demo` に SDK を持たせる。`crypto/{frost,shamir,toprf,aead,kdf}.ts` は byte 凍結コピー。
  `jwt/jwt.ts`, `client-sdk/dpop.ts`, `client-sdk/client.ts`, `nodes/wire.ts` (応答デコード) は
  **ブラウザ移植** として `projects/demo/src/sdk/` に置く。許容する変更は次に限る:
  `Buffer` → `TextEncoder`/`TextDecoder` + 自前 base64url、`node:crypto` の `randomBytes`/`randomUUID`
  → `globalThis.crypto.getRandomValues`/`randomUUID`、`proxy` (インプロセス) 分岐の削除、
  `import` パスの調整。暗号計算の手順・順序・定数は変えない。移植元との `diff` を
  `projects/demo/README.md` に要約する。
- 凍結コピー (`frost.ts` の `computeGroupCommitment`、`kdf.ts` の `deriveRefreshKey`) が Node グローバルの `Buffer` を
  参照するため、`src/sdk/buffer-shim.ts` で **実際に使われる用法だけ** を補完する (それ以外は throw)。凍結コピー自体は編集しない。
- 凍結コピー `toprf.ts` に未使用 import があるため、demo の `tsconfig.json` では `noUnusedLocals` を無効にする (`strict`, `noUnusedParameters` は維持)。
- ブラウザ列の `非保持:` は全イベント共通の 1 文言とする (ブラウザはサインオン時に password を持つ側なので、
  リフレッシュで password を使わないことは `計算:` 行に「password 不使用」として出す)。
- デモ UI は `/api/pasta/sign-on` と `/api/pasta/refresh` を同一オリジンで呼ぶ。
  API 失敗時に **偽トークンを生成するフォールバックは削除** し、エラーを表示する。
- デモ UI の「ログ」タブに第 10 節ブラウザ列のイベントを出し、`console.log` にも同じ行を出す。
- gateway: `/api/pasta/browser-sign-on` を削除。関連テストを削除し、代わりに「パスワードを含む
  ボディを sign-on に送っても無視される (username と blinded のみ使う)」ことは既存の e2e で担保。
  第 6 節の外部 API 表から該当行を削除。
- CLI スタンドイン `projects/demo/cli/sign-on.ts`: ブラウザと同じ SDK を Node で動かし、
  `--gateway URL --user --password --client-id --nonce [--refresh]` で id_token を stdout の最終行に出す。
  第 10 節ブラウザ列のログを stderr に出す。総合テストの「ブラウザ役」として使う
  (`scripts/integration-test.sh` の browser-sign-on 呼び出しを置き換える。Node 20 以上が必要になる
  ことを README に明記し、`projects/demo/node_modules` が無ければテストスクリプトが `npm ci` する)。
  Node 側では `globalThis.crypto` が WebCrypto なので同じコードが動く。

## 12. tmux による並列表示

`scripts/demo-tmux.sh`: `tmux` が無ければインストール方法 (`brew install tmux`) を表示して exit 1。
セッション `pasta-demo` を作り、`docker compose logs -f --no-log-prefix <svc>` を node1, node2, node3,
gateway, rp の 5 ペインで `tiled` レイアウトに並べ、6 つ目のペインに CLI スタンドインの実行例を
プロンプトに入れた shell を開く。`docker compose up -d --wait` 済みであることを前提にし、
未起動なら起動を促す。各ペインのタイトルにサービス名を表示する (`set -g pane-border-status top`)。

## 13. DPoP 鍵を rp フロントに移す (OAuth 化ステップ 1)

決定 (2026-09-06): スコープは OIDC ではなく OAuth。id_token は将来のステップで廃止する。
このステップでは **DPoP 鍵ペアの生成と保管を rp フロント (ブラウザ上の rp ページ) に移し**、
gateway / gateway フロント (デモ UI) / node には公開鍵のサムプリント `jkt` だけを渡す。

### 流れ (変わる箇所)

```
1. rp フロント                    ページ読み込み時に WebCrypto (Ed25519) で DPoP 鍵ペアを生成。
                                  秘密鍵は rp オリジンの IndexedDB に extractable=false で保存。
                                  公開 JWK の RFC 7638 サムプリント = jkt。
2. rp フロント → gateway          GET /authorize?client_id&redirect_uri&response_type&response_mode&scope&nonce&state&dpop_jkt=<jkt>
   gateway    → rp フロント       dpop_jkt を検証 (base64url 43 文字) し、/demo への引き継ぎ URL に dpop_jkt を含める
3. gateway フロント               DPoP 鍵を生成しない。URL の dpop_jkt をそのまま cnfJkt に使う。無ければエラー表示。
4. gateway フロント → gateway     POST /api/pasta/sign-on { ..., cnfJkt = dpop_jkt }
   node                           変更なし (受け取った cnfJkt をセッションに束縛)
7. gateway フロント               id_token を組み立てる (cnf.jkt = rp の鍵)
8. gateway フロント → rp          form_post {id_token, state}
9. rp        → rp フロント        検証結果を表示。rp フロントは保存鍵の jkt とトークンの cnf.jkt の一致を画面で示す。
```

### コンポーネント別

- **rp**: ランディング HTML にインライン JS (依存ゼロ、ビルド無し)。`crypto.subtle.generateKey({name:"Ed25519"}, false, ["sign","verify"])`、
  公開鍵を `exportKey("jwk")` して `{crv,kty,x}` を辞書順で JSON 化し SHA-256 → base64url = jkt (RFC 7638)。
  秘密鍵 `CryptoKey` を IndexedDB (`pasta-rp` / store `dpop`) に保存。ログインボタンは jkt 計算完了後に有効化し、
  `href` に `&dpop_jkt=<jkt>` を付ける。WebCrypto が Ed25519 非対応ならボタンを無効化して理由を表示。
  `/callback` の HTML に「my DPoP jkt」と「token cnf.jkt」を並べ、インライン JS が一致を判定して ✓/✖ を表示
  (サーバ側は cnf.jkt を表示するだけ。鍵はサーバに送らない)。
- **gateway**: `/authorize` で `dpop_jkt` を **必須** とし、`^[A-Za-z0-9_-]{43}$` で検証 (欠落・不正は 400)。
  `/demo?step=login&...&dpop_jkt=<jkt>` へ引き継ぐ。デモログ `authorize` 行に `dpop_jkt=<先頭8>` を追加。
  `src/gateway/oidc.ts` は **このステップから byte 凍結の対象外** (OIDC のグルーコードであり暗号ではない)。
  変更点 (`validateAuthorizeRequest` に `dpopJkt`、`renderAuthorizePage` の URL に `dpop_jkt`) を README に記録。
- **gateway フロント (projects/demo)**: SDK の `DecentralizedClientSdk` から DPoP 鍵生成を外し、`cnfJkt: string` を
  コンストラクタ引数で受ける。`dpop.ts` の鍵生成・proof 生成は SDK 本体から使わなくなる (CLI が使うので残す)。
  `App.tsx` は URL の `dpop_jkt` を読み、無ければサインオンを開始せずエラーを表示。**リフレッシュボタンは削除**
  (秘密鍵が rp フロントにしか無い。リフレッシュは後のステップで `/token` 側に移す)。SDK の `refresh()` は
  DPoP proof を外部から受け取る形に変えるか、このステップでは CLI 専用として残す (いずれかを選び README に記す)。
  ブラウザ列のデモログ `sign-on` 行の `jkt` は「rp から受領」と分かるよう `jkt(rp) <8>` と表記。
- **CLI スタンドイン (projects/demo/cli/sign-on.ts)**: rp フロントと gateway フロントの両方を演じるので、自分で
  DPoP 鍵を生成して `jkt` を SDK に渡す。`--refresh` は自前の鍵で proof を作って継続。`--jkt <値>` で外部指定も可 (秘密鍵が手元に無い想定なので `--refresh` との併用はエラー)。
- **node**: 変更なし。
- **総合テスト**: 既存ステップは CLI 経由なのでそのまま通るはず。追加: `/authorize` が `dpop_jkt` 欠落で 400、
  正しい `dpop_jkt` 付きで 200 かつ応答に `dpop_jkt=` を含む。rp `/` の HTML に `dpop_jkt` を組み立てる JS が含まれる。
- **README / 契約**: 第 6 節の `/authorize` 行と第 7 節の `/` の説明に `dpop_jkt` を追記 (実装エージェントが行う)。

### 成立する性質

DPoP 秘密鍵は rp フロントから出ない。gateway、gateway フロント、node が知るのは jkt だけで、
id_token の `cnf.jkt` は最初から rp の鍵に束縛される。
