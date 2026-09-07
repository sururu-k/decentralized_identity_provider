# デモ UI + ブラウザ用クライアント SDK

分散 IdP (PASTA 2HashTDH TOPRF + FROST しきい値 Ed25519, 2-of-3) の **OAuth 2.0 認可コードフロー**
ログイン画面と、**ブラウザで動くクライアント SDK** を含むプロジェクト。

`docs/container-split.md` 第 14 節の決定により、この端末 (ブラウザ) は SDK を実行して
**認証アサーション** を組み立てる。アサーションは **OAuth の認可コードそのもの** であり、
ノードのグループ署名が付いた短命 (30 秒) の JWT。パスワードを知る者だけが作れる。
gateway はパスワードを一切受け取らず、ブラインド化された点 `A` を中継するだけ。
`id_token` は廃止した (第 14 節)。

このディレクトリは gateway イメージのビルドステージでビルドされ、`/`, `/demo`, `/assets/*` として
配信される (`projects/gateway/Dockerfile` の `ui` ステージ)。

---

## フロー (契約 第 14.1 節)

```
rp フロント → gateway /authorize?response_type=code&client_id&redirect_uri&scope&state&dpop_jkt
gateway    → ブラウザ  /demo?c&dpop_jkt&client_id&redirect_uri&scope&state へリダイレクト
ブラウザ (このプロジェクト)
  1. URL の c / dpop_jkt / client_id / redirect_uri / scope / state を読む
  2. username, password を入力し signOn() を実行
  3. アサーション (認可コード) を組み立てる
  4. redirect_uri?code=<アサーション>&state=<state> へ遷移 (GET)。gateway/node を経由しない
rp フロント (/callback)     code を /token に出して access_token を得る (このプロジェクトの範囲外)
```

- `c` は gateway の認可チャレンジで、アサーションの `nonce` に署名される。
- `dpop_jkt` は rp フロントが持つ DPoP 公開鍵のサムプリント (第 13 節)。このページは DPoP 鍵を
  作らず、受け取った `dpop_jkt` を `cnf.jkt` に束縛するだけ。
- `dpop_jkt` / `c` / `redirect_uri` のいずれかが無ければサインオンを始めず、
  「rp から開始してください」と表示する。

---

## 構成

```
projects/demo/
├── src/
│   ├── App.tsx          デモ UI (ログイン → 同意 → 署名集約 → code で rp へ遷移)
│   ├── main.tsx
│   └── sdk/             ブラウザ用クライアント SDK
│       ├── crypto/      frost / shamir / toprf / aead / kdf — gateway からの byte 凍結コピー
│       ├── buffer-shim.ts  凍結コピーが使う Node の `Buffer` をブラウザに用意する
│       ├── jwt.ts       base64url, deterministicJsonStringify, createSigningInput …
│       ├── dpop.ts      RFC 9449 DPoP 鍵と proof (SDK は使わない。CLI が rp フロント役で使う)
│       ├── wire.ts      sign-on 応答の base64url デコード (第 3 節)
│       ├── types.ts     プロトコル / プロキシ応答の型
│       ├── events.ts    デモログ (第 10 節「ブラウザ」列)
│       ├── client.ts    DecentralizedClientSdk
│       └── index.ts     再エクスポート
├── cli/sign-on.ts       CLI スタンドイン (rp フロント + IdP フロント役、Node 20+)
└── tests/
    ├── sdk.test.ts      移植の byte 一致 + 復号合成テスト (常時実行)
    └── e2e.test.ts      実 gateway に対する CLI 結合テスト (DEMO_E2E_GATEWAY があるときだけ)
```

`src/sdk/crypto/kdf.ts` はリフレッシュ廃止 (第 14 節) で SDK からは使われなくなったが、
凍結コピーとして残す (byte 凍結の対象で、`buffer-shim` の根拠でもある)。

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

---

## 認証アサーション (署名対象)

SDK が組み立て、ノードが署名する。キーは全階層で辞書順 (凍結の `deterministicJsonStringify`)。
`projects/node/README.md` の正規シリアライズと **byte 一致** する。

- ヘッダ: `{"alg":"EdDSA","kid":"pasta-group-key-1","typ":"JWT"}`
- ペイロード (辞書順): `aud`, `client_id`, `cnf.jkt`, `exp`, `iat`, `iss`, `nonce`, `scope`, `sub`
  - `aud` = `iss` = ISSUER (gateway)。アサーションは gateway 宛て。
  - `client_id` はアクセストークンの `aud` になる値。`scope` はそのままアクセストークンへ。
  - `cnf.jkt` は rp フロントの DPoP サムプリント。`nonce` は認可チャレンジ `c`。
  - `exp = iat + 30` (30 秒)。ノードが `exp - iat ≤ 30` を検証する。

`sub` はノードのユーザー記録から返る値を使う。復号 (`ct_i`) の AAD もこの署名対象 (signingInput)
なので、パスワードが違うとこの端末での復号が失敗する。

`tests/sdk.test.ts` が、上記の正規シリアライズを `node:crypto` の `Buffer` で独立に base64url
化した値と `createSigningInput` の出力が一致することを検証し、さらに凍結 crypto で組んだ
フェイクノード応答から復号・集約したアサーションがグループ公開鍵で Ed25519 検証できることを確認する。

---

## CLI スタンドイン

ブラウザと **同じ `src/sdk/`** を Node で実行する。総合テスト (`scripts/integration-test.sh`)
と tmux デモ (`scripts/demo-tmux.sh`) の「ブラウザ役」。rp フロントと IdP フロントの両方を演じる。

```bash
npm run -s sign-on -- \
  --gateway http://localhost:3000 \
  --user alice --password password123 \
  --client-id demo_client --scope "openid profile" [--refresh]
```

既定動作: 自分で DPoP 鍵を生成 → その jkt で signOn しアサーション (認可コード) を得る →
gateway の `POST /token` に `grant_type=authorization_code&code=<アサーション>&client_id&redirect_uri`
と自前鍵の DPoP proof (`htu=<issuer>/token`) を出して **access_token** を得る →
stdout 最終行に出す。

| 引数 | 既定 | 意味 |
|---|---|---|
| `--gateway <url>` | `http://localhost:3000` | gateway のベース URL |
| `--issuer <url>` | `--gateway` と同じ | アサーションの `iss`/`aud`、proof の `htu` の基底 |
| `--user <name>` | `alice` | ユーザー名 |
| `--password <pw>` | (必須) | パスワード |
| `--client-id <id>` | `demo_client` | `client_id` / アクセストークンの `aud` |
| `--scope <scope>` | `openid profile` | `scope` |
| `--nonce <str>` | `cli_<random>` | 認可チャレンジ `c` |
| `--redirect-uri <url>` | `http://localhost:3001/callback` | `/token` に送る `redirect_uri` |
| `--jkt <thumbprint>` | 自前生成 | 外部で持つ DPoP 鍵のサムプリント (43 文字) に束縛。**アサーション出力モード** |
| `--refresh` | off | 得た refresh_token を `grant_type=refresh_token` + 新 proof で使い、新 access_token を出す |

- `--jkt` を渡すと、束縛先の秘密鍵が手元に無いので `/token` を叩けない。この場合は
  **アサーション (認可コード) を stdout に出して終了** する。`--refresh` との併用はエラー (第 13 節)。
- **stdout の最終行がトークン (access_token、または `--jkt` 時はアサーション) だけ**。`| tail -1` で取れる。
- 第 10 節のデモログは **stderr**。stderr が TTY のとき黄色 (`NO_COLOR` で無効、`FORCE_COLOR=1` で強制)。
  `DEMO_LOG=0` でログ自体を止める。
- 失敗時 (誤パスワード等) は stderr に 1 行出して **exit 1**、stdout には何も出さない。

---

## デモログ (契約 第 10 節「ブラウザ / CLI スタンドイン」列)

SDK は各ステップで `onEvent` を呼ぶ。UI は「処理ログ」タブと `console.log` の両方に、
CLI は stderr に、同じ行を出す。サインオンは 1 イベント 3 行 (ブラインド → 応答 → 集約)。
リフレッシュ行は無い (IdP フロントはリフレッシュしない。第 14 節)。

```
[browser] sign-on   user=alice nonce=c_test1  → r 03143e6e  A=r·H1(pw) 0p3KGU8N  jkt(rp) 4XTCTfr2  nonce_s MBYb_D0-
                    ← B_i×3 ct_i×3 (D,E)×3  sess=sess-c_t
                    → h=finalize(pw, unblind(r,B_i))  h_i×3  z_i=dec(ct_i)×3 005e620b 03f43d77 0864afb0  R 5Q1BYOIP  σ=Σz_i  assertion eyJhbGci ✔ (auth code, 30s, aud=gateway)
```

- ステップ id は `signon-blind` → `signon-response` → `signon-aggregate` (UI のノードアニメーションが見ている)。
- `jkt(rp)` の `(rp)` は「この値は rp フロントから受け取ったもので、ここで作った鍵では
  ない」という印 (第 13 節)。最終行は組み立てた **認証アサーション** の先頭 8 文字と
  `(auth code, 30s, aud=gateway)`。
- 誤パスワードは `✖` 1 行 (`rejected:` ではなく `failed:`。誰も拒否していない。AEAD のタグが
  この端末で合わなかっただけで、ノードには分からない):

```
[browser] ✖ sign-on failed: ct_1 decrypt failed → wrong password (nodes cannot tell)
```

- **秘密は出さない**: パスワード、`h`、`h_i` は `onEvent` に渡していない。
  セッション毎の値 (`r`, `A`, `B_i`, `ct_i`, `z_i`, `R`, `sessionNonce`, `cnf.jkt`, `assertion`) は
  先頭 8 文字に切り詰める (`…` は付けない)。

---

## 移植差分 (契約 第 11 節 + 第 14 節)

移植元は `projects/gateway/src/`。§11 で許容されている変更は
`Buffer` → `TextEncoder`/`TextDecoder` + 自前 base64url、`node:crypto` → `globalThis.crypto`、
インプロセス `proxy` 分岐の削除、import パスの調整のみ。§14 で追加された変更は
**署名対象クレーム (id_token → アサーション) と API の形** に限る。**暗号計算の手順・順序・定数・
JSON のキー順は一切変えていない。**

| ファイル | 移植元 | 何を何に置き換えたか |
|---|---|---|
| `src/sdk/crypto/*` | `crypto/*` | **変更なし** (`diff` 無出力)。`kdf.ts` は未使用だが凍結コピーとして残す |
| `src/sdk/jwt.ts` | `jwt/jwt.ts` | `base64UrlEncode`/`base64UrlDecode` を `btoa`/`atob` 経由に。`deterministicJsonStringify` / `createSigningInput` / `assembleJwt` は 1 文字も変えていない |
| `src/sdk/dpop.ts` | `client-sdk/dpop.ts` | `crypto.randomUUID()` → `globalThis.crypto.randomUUID()`。`verifyDPoPProof` を省略。proof のヘッダ・ペイロード・署名入力は同一。SDK 本体は使わず CLI が rp フロント役で使う |
| `src/sdk/wire.ts` | `gateway/wire.ts` | sign-on 応答のデコードのみ残す。リフレッシュ廃止 (§14) でリフレッシュ応答デコードと全エンコード方向を削除。フィールド名は不変 |
| `src/sdk/types.ts` | `protocol/types.ts` + `gateway/proxy.ts` | `SignOnResponse` / `ProxySignOnResult` の型のみ。`ProxySignOnRequestBody` に `clientId` / `scope` を追加し `nonce` を必須に (§14)。リフレッシュ系の型を削除 |
| `src/sdk/client.ts` | `client-sdk/client.ts` | ①`proxy` 分岐と `PastaOAuthProxy` import を削除、`proxyUrl` を必須の `string` に。②`randomBytes` → `getRandomValues`、`Buffer` → `TextDecoder`。③`onEvent` を追加。④`buffer-shim` を先頭 import。⑤**§13**: DPoP 鍵生成を外しコンストラクタ第 2 引数 `cnfJkt` を必須に。⑥**§14**: 署名対象を id_token → アサーション (`client_id`, `scope`, `nonce=c`, `aud=issuer`, `exp=iat+30`)。`ct_i` は `{ z_i }` のみを復号 (`rs_i` 廃止)。**`refresh()` を削除**、戻り値を `{ assertion }` に。ブラインド・`createSigningInput`・`deriveAeadNonce`・AAD・集約順序はすべて移植元と同一 |
| `src/sdk/buffer-shim.ts` | (新規) | 凍結コピーが使う `Buffer.from(...).toString("hex")` / `Buffer.from(str,"utf8")` だけを補完 |
| `src/sdk/events.ts` | (新規) | 第 10 節のログイベント。リフレッシュ用の `DemoStep` を削除 (§14) |
| `src/sdk/index.ts` | (新規) | 再エクスポート |

---

## 画面

`?step=login` (既定) / `?step=consent` / `?step=completed` (`?step=jwt` も可) で開始位置を指定できる。
`?step=completed` は **スクリーンショット用のモック表示** で、実際のサインオンは行われていない
(署名は本物ではない)。画面上に「モック表示です」と明示される。

OAuth 連携パラメータ (`c`, `dpop_jkt`, `client_id`, `redirect_uri`, `scope`, `state`) はクエリから読む。
サインオン成功時は **`redirect_uri?code=<アサーション>&state=<state>` へ遷移** して rp に認可コードを渡す
(`window.location.href`)。gateway/node は経由しない。form_post は廃止した (第 14 節)。

`dpop_jkt` / `c` / `redirect_uri` のいずれかが無いときはサインオンを始めず、
「rp から必要なパラメータが渡されていません。http://localhost:3001/ から開始してください。」と
表示して先へ進むボタンを無効にする。この画面は DPoP 鍵を作らない (第 13 節)。
**リフレッシュボタンは無い**: リフレッシュは rp フロントが `/token` で行う (第 14 節)。

1. **ログイン** — テストアカウント (alice / bob)、パスワード入力。失敗するとここにエラーが出る。
2. **同意** — 要求スコープの確認。
3. **署名集約** — 3 ノードの状態と、ノード通信可視化 / 認証アサーション / 処理ログの 3 タブ。
4. **完了** — 認証アサーション (認可コード) の表示とコピー、rp への遷移。

誤パスワードのときは gateway もノードも正常に応答し、**この端末での `ct_i` 復号だけが失敗する**。
UI はその旨 (「ノードは成否を知りません」) を表示してログイン画面に戻る。

---

## テスト

```bash
npm test                                        # 移植の byte 一致 + 復号合成テストのみ
DEMO_E2E_GATEWAY=http://localhost:3000 npm test # + 実 gateway に対する CLI 結合テスト
```

- `tests/sdk.test.ts` (常時): base64url / `deterministicJsonStringify` / `createSigningInput` /
  `assembleJwt` / DPoP サムプリントの byte 一致、アサーションの正規シリアライズ byte 一致
  (`node:crypto` で独立計算)、そして凍結 crypto で組んだフェイクノード応答からの復号・集約で
  アサーションがグループ公開鍵で検証できること・誤パスワードで AEAD が失敗しセッションが残らないこと。
- `tests/e2e.test.ts` (`DEMO_E2E_GATEWAY` があるときだけ): CLI を子プロセスで動かし、
  `authorize→sign-on→code→/token` で得た access_token を `/jwks.json` の鍵で `node:crypto` により
  Ed25519 検証 (`typ=at+jwt`, `aud=client_id`, `iss`)、`--refresh` の access_token、誤パスワードでの
  exit 1 を確認する。gateway の `/token` は並行実装中なので、対応するまで skip のまま。

---

## 技術ポイント

1. **パスワードはネットワークに出ない (TOPRF)** — 端末で `A = r·H1(pw)` にブラインド化して送る。
   ノードは `B_i = k_i·A` を返すだけで、`r` を知らないので `h` を導けない。
2. **単一障害点のない署名鍵 (FROST 2-of-3)** — 署名シェア `z_i` は `h_i` で暗号化されて返る。
   復号できるのはパスワードを知る端末だけ。ノード 1 台が落ちても 2-of-3 で成立する。
3. **認可コード = 認証アサーション** — 完成する JWT は OAuth の認可コードそのもの。パスワードを
   知る者だけが作れ、30 秒で失効する。gateway も node も状態を持たない (契約 第 14 節)。
4. **DPoP による送信者束縛 (RFC 9449)** — rp オリジンのページが作った Ed25519 鍵に `cnf.jkt` で
   束縛する。鍵を持つのは rp フロントだけで、gateway もこの画面もノードもサムプリントしか
   知らない (第 13 節)。リプレイでアサーションを得ても、束縛先の秘密鍵が無ければトークンを行使できない。
