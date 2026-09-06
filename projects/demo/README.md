# デモ UI + ブラウザ用クライアント SDK

分散 IdP (PASTA 2HashTDH TOPRF + FROST しきい値 Ed25519, 2-of-3) の OAuth 2.0 / OpenID Connect
ログイン画面と、**ブラウザで動くクライアント SDK** を含むプロジェクト。

`docs/container-split.md` 第 11 節の決定により、SDK は gateway ではなく **この端末 (ブラウザ)** で
実行される。gateway はパスワードを一切受け取らず、ブラインド化された点 `A` を中継するだけ。
`id_token` を組み立てられるのはこの端末だけになる。

このディレクトリは gateway イメージのビルドステージでビルドされ、`/`, `/demo`, `/assets/*` として
配信される (`projects/gateway/Dockerfile` の `ui` ステージ)。

---

## 構成

```
projects/demo/
├── src/
│   ├── App.tsx          デモ UI (ログイン → 同意 → 署名集約 → 完了)
│   ├── main.tsx
│   └── sdk/             ブラウザ用クライアント SDK
│       ├── crypto/      frost / shamir / toprf / aead / kdf — gateway からの byte 凍結コピー
│       ├── buffer-shim.ts  凍結コピーが使う Node の `Buffer` をブラウザに用意する
│       ├── jwt.ts       base64url, deterministicJsonStringify, createSigningInput …
│       ├── dpop.ts      RFC 9449 DPoP 鍵と proof
│       ├── wire.ts      base64url ワイヤ形式のデコード (第 3 節)
│       ├── types.ts     プロトコル / プロキシ応答の型
│       ├── events.ts    デモログ (第 10 節「ブラウザ」列)
│       ├── client.ts    DecentralizedClientSdk
│       └── index.ts     再エクスポート
├── cli/sign-on.ts       CLI スタンドイン (ブラウザ役、Node 20+)
└── tests/
    ├── sdk.test.ts      移植の byte 一致テスト (常時実行)
    └── e2e.test.ts      実 gateway に対する結合テスト (DEMO_E2E_GATEWAY があるときだけ)
```

---

## 開発・ビルド

**Node 20 以上が必要** (`globalThis.crypto` が WebCrypto であること、`fetch` 組み込みが前提)。

```bash
npm install
npx tsc --noEmit     # 型チェック
npm test             # ユニットテスト
npm run build        # tsc && vite build → dist/
npm run dev          # vite dev server (:5173, /api を localhost:3000 へプロキシ)
```

`npm run dev` の場合、gateway (`http://localhost:3000`) が起動している必要がある。
`vite.config.ts` が `/api`, `/jwks.json`, `/.well-known`, `/demo/rp-callback` を転送する。

---

## CLI スタンドイン

ブラウザと **同じ `src/sdk/`** を Node で実行する。総合テスト (`scripts/integration-test.sh`)
と tmux デモ (`scripts/demo-tmux.sh`) の「ブラウザ役」。

```bash
npm run -s sign-on -- \
  --gateway http://localhost:3000 \
  --user alice --password password123 \
  --client-id demo_client --nonce n1 [--refresh]
```

| 引数 | 既定 | 意味 |
|---|---|---|
| `--gateway <url>` | `http://localhost:3000` | gateway のベース URL |
| `--issuer <url>` | `--gateway` と同じ | JWT の `iss` に入れる値 |
| `--user <name>` | `alice` | ユーザー名 |
| `--password <pw>` | (必須) | パスワード |
| `--client-id <id>` | `demo_client` | `aud` |
| `--nonce <str>` | `cli_<random>` | OIDC nonce (gateway が必須としている) |
| `--jkt <thumbprint>` | 自前生成 | 外部で持っている DPoP 鍵のサムプリント (43 文字 base64url) に束縛する |
| `--refresh` | off | サインオン後に DPoP リフレッシュも行い、新しいトークンを出す |

CLI は rp フロントの役も兼ねるので、**自分で DPoP 鍵ペアを作り** (`src/sdk/dpop.ts` の
`generateDPoPKeyPair`)、jkt だけを SDK に渡す。`--refresh` の proof もここで署名する。
`--jkt` を渡した場合は秘密鍵が手元に無いという想定なので、`--refresh` との併用はエラー
にする (契約 第 13 節)。

- **stdout の最終行が `id_token` だけ**。それ以外は stdout に出さないので `| tail -1` で取れる。
- 第 10 節のデモログは **stderr**。stderr が TTY のとき黄色 (`NO_COLOR` で無効、`FORCE_COLOR=1` で強制)。
  `DEMO_LOG=0` でログ自体を止める。
- 失敗時は stderr に 1 行出して **exit 1**。

---

## デモログ (契約 第 10 節「ブラウザ / CLI スタンドイン」列)

SDK は各ステップで `onEvent` を呼ぶ。UI は「処理ログ」タブと `console.log` の両方に、
CLI は stderr に、同じ行を出す。サインオンは 1 イベント 3 行 (ブラインド → 応答 → 集約)、
リフレッシュは 1 行。イベント名は専用の桁に左詰めし、2 行目以降はその桁ぶん字下げする
ので、node / gateway / rp の列と縦が揃う。

```
[browser] sign-on   user=alice nonce=compact-1  → r 03a6a618  A=r·H1(pw) mNDkmKAj  jkt(rp) y7VfmjvC  nonce_s ueP7c3cV
                    ← B_i×3 ct_i×3 (D,E)×3  sess=8fa90b5e
                    → h=finalize(pw, unblind(r,B_i))  h_i×3  z_i=dec(ct_i)×3 0cf04b76 03f856be 0c291ff0  R xelLAdz2  σ=Σz_i  id_token eyJhbGci ✔ assembled only here
[browser] refresh   sess=8fa90b5e ctr=1  → DPoP proof  ← ct_i×3 (D,E)×3  → rk_i=HKDF(rs_i,ctr)×3  z_i×3 0052be15 06ba9a3e 0d80606d  R aWavm7Lx  σ  new id_token eyJhbGci ✔
```

- ステップ id は `signon-blind` → `signon-response` → `signon-aggregate`、リフレッシュは
  `refresh` (UI のノードアニメーションがこれを見ている)。
- `jkt(rp)` の `(rp)` は「この値は rp フロントから受け取ったもので、ここで作った鍵では
  ない」という印 (契約 第 13 節)。
- 誤パスワードは `✖` 1 行。他コンポーネントの `rejected:` ではなく `failed:` を使う
  (誰も拒否していない。AEAD のタグがこの端末で合わなかっただけで、ノードには分からない):

```
[browser] ✖ sign-on failed: ct_1 decrypt failed → wrong password (nodes cannot tell)
```

- **秘密は出さない**: パスワード、`h`、`h_i` は `onEvent` に渡していない。
  セッション毎の値 (`r`, `A`, `B_i`, `ct_i`, `z_i`, `R`, `sessionNonce`, `cnf.jkt`, `id_token`) は
  先頭 8 文字に切り詰める (`…` は付けない)。
- `never:` の宣言はブラウザ列には出さない。ブラウザはパスワードを持つ側であり、`✔ assembled
  only here` が「この端末だけが id_token を組み立てた」ことを示す。

---

## 移植差分 (契約 第 11 節)

移植元は `projects/gateway/src/`。許容されている変更は
`Buffer` → `TextEncoder`/`TextDecoder` + 自前 base64url、`node:crypto` → `globalThis.crypto`、
インプロセス `proxy` 分岐の削除、import パスの調整のみ。
**暗号計算の手順・順序・定数・JSON のキー順は一切変えていない。**

| ファイル | 移植元 | 何を何に置き換えたか |
|---|---|---|
| `src/sdk/crypto/frost.ts` | `crypto/frost.ts` | **変更なし** (`diff` 無出力) |
| `src/sdk/crypto/shamir.ts` | `crypto/shamir.ts` | **変更なし** |
| `src/sdk/crypto/toprf.ts` | `crypto/toprf.ts` | **変更なし** |
| `src/sdk/crypto/aead.ts` | `crypto/aead.ts` | **変更なし** |
| `src/sdk/crypto/kdf.ts` | `crypto/kdf.ts` | **変更なし** |
| `src/sdk/jwt.ts` | `jwt/jwt.ts` | `base64UrlEncode`: `Buffer.from(...).toString("base64url")` → `TextEncoder` + `btoa` + アルファベット置換 + パディング除去。`base64UrlDecode`: `Buffer.from(s,"base64url")` → `-`/`_` 復元 + 再パディング + `atob`。`verifyJwt` の `Buffer.from(b64,"base64url").toString("utf8")` → `TextDecoder(base64UrlDecode(...))`。`deterministicJsonStringify` / `createSigningInput` / `assembleJwt` は 1 文字も変えていない |
| `src/sdk/dpop.ts` | `client-sdk/dpop.ts` | `import crypto from "node:crypto"` を削除し `crypto.randomUUID()` → `globalThis.crypto.randomUUID()`。**`verifyDPoPProof` と `VerifyDPoPProofOptions` / `VerifyDPoPProofResult` を省略** (検証はノードの役割で、ブラウザでは使わない。実装は `Buffer.from(s,"base64url")` に依存していた)。`verifyEd25519` の import も不要になったので落とした。proof のヘッダ・ペイロード・署名入力は同一 |
| `src/sdk/wire.ts` | `gateway/wire.ts` | デコード方向 (`signOnResultFromWire`, `refreshResultFromWire`, `commitmentFromWire`) のみ残し、エンコード方向 (`*ToWire`, `commitmentToWire`) と `base64UrlEncode` の import を削除。ブラウザは応答を読むだけで作らない。ワイヤのフィールド名は不変 |
| `src/sdk/types.ts` | `protocol/types.ts` + `gateway/proxy.ts` | `SignOnResponse` / `RefreshResponse` を `protocol/types.ts` から、`ProxySignOnRequestBody` / `ProxySignOnResult` / `ProxyRefreshRequestBody` / `ProxyRefreshResult` を `proxy.ts` から型だけ持ち込んだ。クライアントが使わない `SignOnRequest` / `RefreshRequest` は入れていない |
| `src/sdk/client.ts` | `client-sdk/client.ts` | ①`proxy` (インプロセス) 分岐と `PastaOAuthProxy` import を削除。あわせて `proxyUrl` を **必須の `string`** にした (移植元は真偽値判定だったので `""` = 同一オリジンを表現できなかった)。②`crypto.randomBytes(16)` → `new Uint8Array(16)` + `globalThis.crypto.getRandomValues`。③`JSON.parse(Buffer.from(bytes).toString("utf8"))` → `JSON.parse(new TextDecoder().decode(bytes))` (2 箇所)。④`onEvent` 進行コールバックを追加 (第 10 節のログ用、1 呼び出し = 1 行)。⑤`import "./buffer-shim.js"` を先頭に追加。⑥**第 13 節**: DPoP 鍵生成を外し、コンストラクタ第 2 引数 `cnfJkt: string` を必須にした (`generateDPoPKeyPair` / `exportDPoPJwk` / `calculateJwkThumbprint` の import と `getDPoPKeyPair()` を削除、`StoredSession.dpopKeyPair` も削除)。`refresh()` は `options.dpopProof` を必須で受け取り、`createDPoPProof` を呼ばなくなった。ブラインド、header/payload オブジェクトとそのキー順、`createSigningInput`、`deriveAeadNonce` の引数、`aeadDecrypt` の AAD、集約順序はすべて移植元と同一 |
| `src/sdk/buffer-shim.ts` | (新規) | 下記参照 |
| `src/sdk/events.ts` | (新規) | 第 10 節のログイベント。移植元には無い |
| `src/sdk/index.ts` | (新規) | 再エクスポート |

`tests/sdk.test.ts` が、移植元を Node で実行して得た固定値と突き合わせて
`base64UrlEncode` / `base64UrlDecode` / `deterministicJsonStringify` / `createSigningInput` /
`assembleJwt` / `calculateJwkThumbprint` の出力一致を検証する。

### `buffer-shim.ts` が必要な理由

契約 第 11 節は `crypto/*` を **byte 凍結コピー** と定めているが、凍結対象の 2 ファイルが
Node のグローバル `Buffer` を使っている。

- `frost.ts` の `computeGroupCommitment`: `Buffer.from(comm.D).toString("hex")`
- `kdf.ts` の `deriveRefreshKey`: `Buffer.from(sessionId, "utf8")`

これらを書き換えると byte 一致が壊れるので、代わりに **足りないグローバルを補う**。
`buffer-shim.ts` は `Buffer` が未定義のときだけ `globalThis.Buffer` を定義し、
上記 2 用法だけを実装する (それ以外のエンコーディングは黙って違う結果を返さず throw する)。
Node (CLI・vitest) では本物の `Buffer` があるので何もしない。

### `tsconfig.json` の `noUnusedLocals`

凍結コピーの `toprf.ts` は `shamir.js` から `mod` を import しているが使っていない
(gateway の tsconfig はこの検査を有効にしていない)。デモ側だけ検査を有効にしたままにすると
凍結コピーの編集が必要になるため、`noUnusedLocals` を `false` にした。
`noUnusedParameters` と `strict` はそのまま有効。

---

## 画面

`?step=login` (既定) / `?step=consent` / `?step=completed` (`?step=jwt` も可) で開始位置を指定できる。
`?step=completed` は **スクリーンショット用のモック表示** で、実際のサインオンは行われていない。
画面上に「モック表示です」と明示される。ログイン画面からやり直すと本物のフローになる。

OAuth 連携パラメータ (`client_id`, `nonce`, `redirect_uri`, `state`, `dpop_jkt`) はクエリから読み、
完了画面の「RP へ form_post で直接送信」で `redirect_uri` に POST する。
`redirect_uri` が無ければ gateway の `/demo/rp-callback` に送る。

`dpop_jkt` が無いときはサインオンを始めず、「rp から dpop_jkt が渡されていません。
http://localhost:3001/ から開始してください。」と表示して先へ進むボタンを無効にする。
この画面は DPoP 鍵を作らない (契約 第 13 節)。**リフレッシュボタンは削除した**: 秘密鍵は
rp オリジンにしか無く、この画面では proof を作れない。リフレッシュは後のステップで
`/token` 側に移る。

1. **ログイン** — テストアカウント (alice / bob)、パスワード入力。失敗するとここにエラーが出る。
2. **同意** — 要求スコープの確認。
3. **署名集約** — 3 ノードの状態と、ノード通信可視化 / JWT / 処理ログの 3 タブ。
4. **完了** — JWT の表示とコピー、RP への form_post 送信。

誤パスワードのときは gateway もノードも正常に応答し、**この端末での `ct_i` 復号だけが失敗する**。
UI はその旨 (「ノードは成否を知りません」) を表示してログイン画面に戻る。
API 失敗時に偽のトークンを作るフォールバックは第 11 節の通り削除した。

---

## テスト

```bash
npm test                                        # 移植の byte 一致テストのみ
DEMO_E2E_GATEWAY=http://localhost:3000 npm test # + 実 gateway に対する結合テスト
```

結合テスト (`tests/e2e.test.ts`) は `docker compose up -d --build --wait` 済みのスタックに対して
alice のサインオン → `/jwks.json` の鍵で `node:crypto` による Ed25519 検証 → DPoP リフレッシュ →
誤パスワードでの復号失敗、を確認する。テスト自身が rp フロント役として DPoP 鍵を作り、
SDK には jkt だけを渡し、リフレッシュの proof も自分で署名する。検証に SDK 自身の `verifyJwt` を使わないのは、
「SDK とコードを共有しない第三者が普通の Ed25519 JWT として検証できる」ことを示すため。

---

## 技術ポイント

1. **パスワードはネットワークに出ない (TOPRF)** — 端末で `A = r·H1(pw)` にブラインド化して送る。
   ノードは `B_i = k_i·A` を返すだけで、`r` を知らないので `h` を導けない。
2. **単一障害点のない署名鍵 (FROST 2-of-3)** — 署名シェア `z_i` は `h_i` で暗号化されて返る。
   復号できるのはパスワードを知る端末だけ。ノード 1 台が落ちても 2-of-3 で成立する。
3. **DPoP による送信者束縛 (RFC 9449)** — rp オリジンのページが作った Ed25519 鍵に `cnf.jkt` で
   束縛し、リフレッシュはその鍵の proof を要求する。鍵を持つのは rp フロントだけで、
   gateway もこの画面もノードもサムプリントしか知らない (契約 第 13 節)。
