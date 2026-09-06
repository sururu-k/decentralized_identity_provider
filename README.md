# 分散型アイデンティティプロバイダ (Decentralized IdP)

PASTA (CCS 2018) と FROST (RFC 8032 Ed25519) に基づく、ゼロ知識中継型 OAuth 2.0 / OpenID Connect の参照実装です。
初期検討時のホワイトボード（`pic/2026-08-23_13-31-28.png`）右側に描かれた構想「OAuth プロキシで形を戻す」を具現化し、従来の OAuth が抱える「認可サーバ（AS）への権限と信頼の一点集中」を暗号プロトコルの組み合わせによって排除します。

学術論文 PASTA の暗号プロトコルをそのまま配備すると、クライアントが複数の分散ノードと直接通信する必要が生じ、既存の OAuth 2.0 / OpenID Connect (OIDC) エコシステムと断絶します。
本システムは、単一の認可サーバとして振る舞う「OAuth プロキシ」を前面に配置し、背後に分散ノード群を隠蔽することで、RP（リライング・パーティ）側の無改造運用と暗号学的な分散安全性を両立させました。

---

## 1. 全体アーキテクチャ（OAuth プロキシによる統合）

ホワイトボード右側の構想を具現化した全体の通信・暗号フローを以下に示します。

```mermaid
sequenceDiagram
    autonumber
    actor User as ユーザー
    participant Browser as ブラウザ (Client SDK)
    participant RP as RP (クライアントWebサービス)
    participant Proxy as OAuth プロキシ (Gateway)
    participant Nodes as 分散IdPノード群 (t=2 / n=3)

    User->>Browser: ログイン操作（ID / パスワード入力）
    RP->>Browser: 認可要求リダイレクト (/authorize, response_mode=form_post)
    Browser->>Browser: 1. 一時 DPoP 鍵ペア生成 (RFC 9449) -> cnf.jkt 導出
    Browser->>Browser: 2. パスワード目隠し暗号化: A = r * H1(pw) in Ristretto255
    Browser->>Proxy: サインオン要求中継 (sub, A, cnf.jkt, nonce, aud)
    Note over Proxy: プロキシは生のパスワードも平文トークンも見えない
    Proxy->>Nodes: 目隠し値 A とコンテキストをブロードキャスト
    Note over Nodes: パスワードを照合せず、ブラインド値に対して部分計算
    Nodes->>Nodes: 3. TOPRF 評価: B_i = k_i * A
    Nodes->>Nodes: 4. FROST 署名シェア生成: z_i = d_i + rho_i * e_i + lambda_i * s_i * c
    Nodes->>Nodes: 5. シェア暗号化: ct_i = ChaCha20Poly1305_{h_i}(z_i || rs_i)
    Nodes-->>Proxy: 暗号化応答の返送 (B_i, ct_i)
    Proxy-->>Browser: 暗号文のままブラウザへ中継
    Browser->>Browser: 6. TOPRF 結合・ブラインド解除: v = r^{-1} * sum(lambda_i * B_i)
    Browser->>Browser: 7. 鍵導出: h = H2(pw, v), h_i = H3(h, i)
    Browser->>Browser: 8. シェア復号: ct_i から z_i と rs_i を取り出す
    Browser->>Browser: 9. 署名集約: z = sum(z_i) mod l
    Browser->>Browser: 10. 標準 EdDSA (Ed25519) JWT の構築
    Browser->>RP: 11. form_post による id_token の直接送信 (プロキシをバイパス)
    RP->>Proxy: /jwks.json 取得 (グループ単一公開鍵 Y)
    RP->>RP: 12. 標準 Ed25519 署名検証および cnf.jkt の確認
```

### サーバー構成（コンポーネント配置）

```mermaid
graph TB
    Browser["ブラウザ (Client SDK)<br>DPoP 鍵生成・ブラインド暗号化・署名集約"]
    RP["RP (クライアント Web サービス)<br>redirect_uri で id_token 受信<br>JWKS で Ed25519 検証"]
    Proxy["OAuth プロキシ / Gateway<br>/.well-known  /jwks.json<br>/authorize  /api/pasta/sign-on<br>/api/pasta/refresh"]
    N1["ノード 1<br>TOPRF 部分評価 B_1<br>FROST 署名シェア z_1<br>ChaCha20-Poly1305 暗号化"]
    N2["ノード 2<br>TOPRF 部分評価 B_2<br>FROST 署名シェア z_2<br>ChaCha20-Poly1305 暗号化"]
    N3["ノード 3<br>TOPRF 部分評価 B_3<br>FROST 署名シェア z_3<br>ChaCha20-Poly1305 暗号化"]

    RP -->|"認可要求リダイレクト<br>/authorize"| Browser
    Browser -->|"ブラインド値 A, cnf.jkt<br>/api/pasta/sign-on"| Proxy
    Proxy -->|"ブラインド値 A をブロードキャスト"| N1 & N2 & N3
    N1 & N2 & N3 -->|"暗号化応答 (B_i, ct_i)"| Proxy
    Proxy -->|"暗号文のまま中継"| Browser
    Browser -->|"id_token を form_post<br>（プロキシ経由なし）"| RP
    RP -->|"/jwks.json 取得"| Proxy
```

### コンテナ構成（`docker-compose.yml`）

上図の論理配置を、そのままコンテナ 1 つずつに割り当てたものです。設計契約は
[`docs/container-split.md`](./docs/container-split.md)。

```mermaid
graph TB
    subgraph host["ホスト"]
        Browser["ブラウザ (Client SDK)"]
    end

    subgraph compose["docker compose ネットワーク"]
        Dealer["dealer (one-shot)<br>FROST / TOPRF 鍵生成<br>alice, bob を事前登録"]
        Secrets[("secrets/<br>group.json<br>node-1..3.json")]
        GW["gateway :3000<br>OIDC / OAuth プロキシ<br>デモ UI 配信"]
        RPC["rp :3001<br>ZK-App Portal<br>JWKS で Ed25519 検証"]
        NA["node1 :4001"]
        NB["node2 :4002"]
        NC["node3 :4003"]
    end

    Dealer -->|"書き込み (--if-missing)"| Secrets
    Secrets -.->|"node-N.json (ro)"| NA & NB & NC
    Secrets -.->|"group.json (ro)"| GW

    Browser -->|"localhost:3001"| RPC
    Browser -->|"localhost:3000"| GW
    GW -->|"NODE_URLS<br>/commit /sign-on /refresh"| NA & NB & NC
    RPC -->|"IDP_INTERNAL_URL<br>gateway:3000/jwks.json"| GW
    Browser -->|"id_token を form_post<br>（gateway を経由しない）"| RPC
```

起動順は `depends_on` で固定されています。`dealer` の
`service_completed_successfully` を node1..3 が待ち、3 ノードの
`service_healthy` を gateway が待ち、gateway の `service_healthy` を rp が待ちます。

---

## 2. 「プロキシが Token を持たない」の成立メカニズム

ホワイトボードの核心である「AS の位置に座るが、プロキシ自身は Token を持たない」という性質は、以下の二つの設計によって成立しています。

### (1) `response_mode=form_post` によるトークン経路の短絡

古典的な OAuth 認可コードフローでは、RP が `/token` エンドポイントを直接叩いて認可コードをトークンと交換します。この経路を採用すると、プロキシ自身がトークンを生成または保持しなければならず、「プロキシが Token を持たない」という前提が崩壊します。

現行システムでは OIDC 標準仕様の `response_mode=form_post` を採用しました。
ブラウザが分散ノードの暗号化シェアを端末内で集約して `id_token`（JWT）を完成させ、ブラウザ上の自動サブミットフォームを経由して RP の `redirect_uri` へ直接 POST 送信します。
プロキシはトークン配送経路から完全に排除されています。

### (2) パスワードと署名シェアの二重秘匿

- **入力の秘匿**: ブラウザ内でパスワード $pw$ にランダムスカラー $r$ を乗じたブラインド点 $A = r \cdot H_1(pw)$ のみが送信されます。プロキシはもちろん、分散ノード群も平文パスワードを知ることはできません。
- **出力の秘匿**: 各ノードが生成した署名シェア $z_i$ は、正しいパスワードからのみ導出できる対称鍵 $h_i$ によって ChaCha20-Poly1305 で暗号化されます。プロキシは $h_i$ を計算できないため、中継する暗号文 $ct_i$ を復号できません。

結果として、プロキシが完全に乗っ取られた場合でも、署名鍵シェアの窃取やトークンの偽造・盗聴は構造的に不可能であり、被害はサービスの可用性阻害（DoS）にとどまります。

---

## 3. 適用されている暗号技術の対応一覧

| 処理フェーズ | 担当主体 | 採用暗号方式 | 役割・防護対象 |
|:---|:---|:---|:---|
| パスワード目隠し | ブラウザ | Ristretto255 群上の乗法ブラインド | ネットワークおよびサーバに対するパスワード秘匿 |
| 閾値認証評価 | 分散ノード (t-of-n) | 2HashTDH TOPRF (Ristretto255) | サーバがパスワードを知らずに正しい認証鍵を共同評価 |
| トークン閾値署名 | 分散ノード (t-of-n) | FROST (RFC 9591 準拠 Ed25519 Schnorr) | 単一障害点のない Ed25519 グループ秘密鍵による分散署名 |
| シェア伝送保護 | 分散ノード $\to$ ブラウザ | ChaCha20-Poly1305 (RFC 8439) | パスワード所有者のみが復号可能。AAD によるセッション束縛 |
| クライアント拘束 | ブラウザ $\leftrightarrow$ RP | RFC 9449 DPoP (Ephemeral Ed25519) | トークン盗難時の他者利用防止 (`cnf.jkt` バインド) |
| トークン検証 | RP | RFC 8032 標準 Ed25519 検証 | 既存の OAuth / JWT 検証器による単一公開鍵検証 |

---

## 4. ホワイトボードの論点（穴①〜⑦）に対する現行の解決状況

`docs/whiteboard-gaps.md` で整理された未決事項に対する、現行実装での回答と到達度を以下に示します。

| # | ホワイトボード時の論点 | 深刻度 | 現行実装での解決方針と到達状態 |
|:--:|:---|:---:|:---|
| ① | オリジン問題 (JS配布の正当性) | 致命 | ブラウザ拡張機能・ネイティブクライアントによる配信の固定、または WebAuthn パスキーとの併用設計として整理。 |
| ② | フロー未定 (プロキシのトークン保持) | 致命 | **`response_mode=form_post` を採用**。ブラウザから RP へ直接 POST することで完全解決。 |
| ③ | 失敗観測不能 (レート制限不可) | 致命 | サーバから成否が区別できない暗号特性を受け入れ、試行総数カウント方式およびクライアントパズル方式による緩和策へ整理。 |
| ④ | PoP トークンの用語混乱 | 軽微 | **RFC 9449 DPoP を正式採用**。リクエストごとに動的生成される DPoP proof とアクセストークンの `cnf.jkt` 束縛を分離実装。 |
| ⑤ | REFRESH の定足数交差不可能性 | 原理的限界 | 各ノードが独立に DPoP 署名を検証する **RFC 9700 sender-constrained 方式を実装**。定足数交差 $2t - n > t - 1$ の境界条件を論文の学術的帰結として位置付け。 |
| ⑥ | `sub` / `aud` のノードへの露出 | 中度 | ドメインごとのソルト付き決定論的擬似識別子（Pairwise Pseudonymous ID）の導出仕様を策定。 |
| ⑦ | ephemeral key の保管場所 | 中度 | WebCrypto non-extractable 属性と IndexedDB の併用によるブラウザ内セキュア保管モデルを策定。 |

---

## 5. 従来の OAuth 2.0 / OIDC との比較

| 項目 | 従来の集権型 IdP (Auth0, Okta 等) | 本方式 (PASTA + FROST + OAuth プロキシ) |
|:---|:---|:---|
| **署名鍵の管理** | 単一サーバ / HSM 内で一括保管（侵害時は全滅） | $n$ 台の独立ノードに秘密分散（$t-1$ 台の侵害まで鍵漏洩なし） |
| **IdP 侵害時の影響** | 任意ユーザーへのなりすまし・全トークン偽造 | 鍵シェアの漏洩なし。トークン偽造不可 |
| **パスワードの扱い** | サーバ側でハッシュ照合（漏洩時はオフライン攻撃可能） | サーバは照合せず、暗号シェアの鍵としてのみ機能（オフライン攻撃不可） |
| **トークン配送経路** | AS が生成し、直接またはコード経由で発行 | ブラウザが端末内で集約し、`form_post` で直接 RP へ伝送 |
| **プロキシの信頼度** | プロキシ＝AS であり完全な信頼が必要 | 暗号中継器に過ぎず、平文トークンを持たないゼロ知識プロキシ |
| **RP 側の変更コスト** | 標準 OIDC クライアントライブラリを使用 | **変更不要**。単一の JWKS URL を参照し標準 Ed25519 で検証可能 |

---

## 6. デモ UI 実動画面

実装された React デモ UI（`projects/demo/`）の各ステップの実際の画面キャプチャです。

この UI は **クライアント SDK をブラウザ内で実行** します (`projects/demo/src/sdk/`)。
ブラインド化・`ct_i` の復号・署名の集約はすべてこの端末で起き、gateway はパスワードを
一切受け取りません。API が失敗したときに偽のトークンを作るフォールバックは無く、
エラーがそのまま画面に出ます。3. の「処理ログ」タブに、下の
「デモの進め方」で見るブラウザ列と同じ行が表示されます。

| 1. ログイン画面 (`pic/screenshot_login.png`) | 2. 認可同意画面 (`pic/screenshot_consent.png`) |
|:---:|:---:|
| ![ログイン画面](pic/screenshot_login.png) | ![認可同意画面](pic/screenshot_consent.png) |
| パスワード目隠し（PASTA）による安全認証 | 要求スコープ確認と FROST 稼働状況 |

| 3. 分散署名・集約完了 (`pic/screenshot_completed.png`) | 4. JWT トークン検証 (`pic/screenshot_jwt.png`) |
|:---:|:---:|
| ![分散署名完了](pic/screenshot_completed.png) | ![JWT検証](pic/screenshot_jwt.png) |
| 端末内署名集約と `form_post` 送信導線 | 標準 EdDSA (Ed25519) JWT と `cnf.jkt` |

---

## 7. クイックスタート

### 動作環境
- Docker Engine 24 以上 / Docker Compose v2.23 以上 (`--wait` を使うため) ※コンテナ起動に必須
- **Node.js v20 以上**
  - **総合テスト (`scripts/integration-test.sh`) とデモ CLI (`projects/demo` の `npm run sign-on`) に必須**。
    どちらもブラウザと同じクライアント SDK を Node で実行するため、`globalThis.crypto` が WebCrypto であること・`fetch` が組み込みであることを前提にしています。
  - 各コンポーネント (`dealer`, `node`, `gateway`, `rp`) のローカル開発・単体テストにも使います。
  - `docker compose up` でスタックを起動してブラウザから触るだけなら不要です。
- tmux 3.x ※`scripts/demo-tmux.sh` で 5 列のログを並べる場合のみ (`brew install tmux`)

### Docker Compose での起動（推奨）

4 コンポーネント (`dealer`, `node` ×3, `gateway`, `rp`) をまとめて立ち上げます。

```bash
# secrets/ はホスト側に先に作る (bind mount 先が root 所有で作られるのを防ぐ)
mkdir -p secrets

# ビルドして起動し、全サービスが healthy になるまで待つ
docker compose up -d --build --wait

# 停止 (secrets/ は残るので、次回起動しても鍵は同じ)
docker compose down
```

初回は `dealer` が `secrets/` に鍵シェアとユーザーレコードを書き出します。2 回目以降は
`--if-missing` が効いて何も書かないため、**再起動しても鍵は変わりません**。鍵を作り直す
場合のみ以下を実行します。

```bash
docker compose down && rm -rf secrets
```

#### 公開ポート

| サービス | コンテナ | ホスト公開ポート | URL |
|:--|:--|:--:|:--|
| gateway (OAuth プロキシ + デモ UI) | `gateway` | 3000 | [http://localhost:3000](http://localhost:3000) |
| rp (ZK-App Portal) | `rp` | 3001 | [http://localhost:3001](http://localhost:3001) |
| ノード 1 | `node1` | 4001 | `http://localhost:4001/health` (デバッグ用) |
| ノード 2 | `node2` | 4002 | `http://localhost:4002/health` (デバッグ用) |
| ノード 3 | `node3` | 4003 | `http://localhost:4003/health` (デバッグ用) |

ノードのポートはデバッグ用の公開です。gateway はコンテナ間ネットワーク
(`http://node1:4001` など) でノードを呼びます。

#### 総合テスト

compose 構成そのものを外側から検証するスクリプトです。起動から、**ブラウザ役 CLI**
(`projects/demo/cli/sign-on.ts`) でのトークン取得、外部検証器 (`node:crypto` のみ、
IdP コード不使用) による Ed25519 検証、rp への form_post、デモログの中身、DPoP
リフレッシュ、誤パスワード、ノード 1 台停止での 2-of-3 継続、2 台停止での失敗、復旧、
鍵の永続まで 120 項目を確認します (手元の Mac で約 75 秒)。

```bash
scripts/integration-test.sh

# スタックを落とさずに残して調べたいとき
KEEP_UP=1 scripts/integration-test.sh
```

「ブラウザ役」は gateway ではなく **ブラウザで動くのと同じ SDK** を Node で実行する CLI
です。そのため **Node.js 20 以上が必要** で、`projects/demo/node_modules` が無ければ
スクリプトが自動で `npm ci` します。

デモログの検証ステップでは、`docker compose logs` を読んで次を確認します。

- gateway の `sign-on   sess=<id>` の行に今回の `nonce` と `user=alice` が同居し、続く行に
  中継の内訳 (`round1 (D,E)×3 → round2 … no h_i, cannot decrypt`) が出ている
- node1..3 に **gateway と同じ `sess=`** の `sign-on` が出ている
- rp に `callback` と `Ed25519 ✓`、`sub=usr_alice_12345` が出ている
- **全サービスのログに `password123` が 0 件**、`secrets/node-1.json` の `secretKeyShare` の断片も 0 件
- node3 を止めたときの gateway ログに `(node3 unreachable, excluded)` が出る

終了時に `docker compose down` します (`--volumes` は付けないので `secrets/` は残ります)。
全項目が通れば exit 0、1 つでも落ちれば exit 1 です。

### デモの進め方

5 つのサービスのログを横に並べ、1 回のログインが各列にどう映るかを見せる手順です。
狙いは一点、**「ブラウザ (この端末) 以外は `id_token` を組み立てる材料を揃えられない」**
ことを、動いているログで示すことです。

#### 1. スタックを起動する

```bash
mkdir -p secrets
docker compose up -d --build --wait
```

#### 2. 5 列のログを並べる

```bash
brew install tmux        # 未導入なら (macOS)
scripts/demo-tmux.sh     # tmux セッション pasta-demo を作って attach
```

`pasta-demo` セッションに 6 ペインが開きます。node1 / node2 / node3 / gateway / rp の
5 ペインが `docker compose logs -f --no-log-prefix` を流し、6 つ目にブラウザ役 CLI の
実行例が **入力済み・未実行** の状態で置かれます (Enter を押すと走ります)。

| 環境変数 / 引数 | 効果 |
|:--|:--|
| `scripts/demo-tmux.sh --up` | スタックが起動していなければ `docker compose up -d --build --wait` してから開く |
| `TAIL=0 scripts/demo-tmux.sh` | 過去ログを出さず、これから起きることだけを表示する |

既定は `--tail=5` です。`--tail=0` にすると各サービスの `● up` イベント
(`holds:` / `never:` — 何を持って立ち上がり、何を構造的に持ち得ないか) が流れて消えて
しまうため、起動直後の状態が画面に残るようにしています。

セッションを閉じるときは `tmux kill-session -t pasta-demo` です。

#### 3. ログインする

ブラウザで [http://localhost:3001/](http://localhost:3001/) を開き、「PASTA IdP でログイン」
から **alice / password123** でログインします (rp → gateway `/authorize` → デモ UI →
form_post → rp `/callback` の一本道)。

tmux の 6 つ目のペインで CLI を走らせても、**ブラウザと同じ SDK** が同じ順序で同じ計算を
します。

```bash
cd projects/demo && npm run -s sign-on -- \
  --gateway http://localhost:3000 --user alice --password password123 \
  --client-id demo_client --nonce demo-1
```

`id_token` が stdout の最終行に、ブラウザ列のデモログが stderr に出ます。

#### 4. 各列の見どころ

同じログインが 5 列に同時に映ります。`sess=` が同じ行を追いかけてください。ログの本文は
英語で、`←` が受け取ったもの、`→` が計算したものです。何を構造的に持ち得ないかは各列の
`● up` 行の `never:` に 1 度だけ書かれます。

**node (青)** — 自分のシェアで部分計算しただけ。`A` はブラインド化済みでパスワードを
復元できず、`z_i` は 3 分の 1 のシェアで単独では無意味、`ct_i` は自分の `h_i` でしか
復号できません。

```
[node1]   ● up      id=1 t=2/3 users=alice,bob   holds: s_1, k_1, h_1(alice,bob)   never: pw, h, other s_i/k_i, id_token
[node1]   sign-on   sess=8fa90b5e round=ef54f65f user=alice  ← A mNDkmKAj  (D,E)×3  nonce_s ueP7c3cV  jkt y7VfmjvC
                    → B_1=k_1·A YAU77MtM  ct_1=AEAD_h1(z_1‖rs_1) VchRFz8J
```

**gateway (マゼンタ)** — `A` と `ct_i` を中継するだけ。`h_i` を持たないので `ct_i` を
復号できず、`r` を知らないので `B_i` から `h` を導けません。

```
[gateway] ● up      t=2/3 nodes=3 issuer=http://localhost:3000   holds: group pubkey, kid=pasta-group-key-1   never: s_i, k_i, h_i, pw, id_token
[gateway] sign-on   sess=8fa90b5e round=ef54f65f user=alice nonce=compact-1  ← A mNDkmKAj  jkt y7VfmjvC  (no pw)
                    round1 (D,E)×3 → round2 ← B_i×3 ct_i×3 (no h_i, cannot decrypt) → relayed as-is
```

**rp (緑)** — `id_token` は **ブラウザから form_post で直接** 届きます。gateway を
経由していないので、gateway 側のログにトークンは 1 度も現れません。

```
[rp]      ● up      issuer=http://localhost:3000   holds: JWKS(kid) only   never: pw, A, B_i, ct_i, any node traffic
[rp]      callback  state=compact-2  ← id_token eyJhbGci (direct from browser, not via gateway)
                    JWKS kid=pasta-group-key-1 → Ed25519 ✓  iss ✓  aud ✓  exp 3598s  sub=usr_alice_12345
```

**ブラウザ / CLI (黄)** — ここだけが `ct_i` を復号して `z_i` を集め、署名を完成させて
います。**この端末だけが `id_token` を組み立てた**、が結論です。

```
[browser] sign-on   user=alice nonce=compact-1  → r 03a6a618  A=r·H1(pw) mNDkmKAj  jkt y7VfmjvC  nonce_s ueP7c3cV
                    ← B_i×3 ct_i×3 (D,E)×3  sess=8fa90b5e
                    → h=finalize(pw, unblind(r,B_i))  h_i×3  z_i=dec(ct_i)×3 0cf04b76 03f856be 0c291ff0  R xelLAdz2  σ=Σz_i  id_token eyJhbGci ✔ assembled only here
```

`password123` はどの列にも出ません。gateway もノードもパスワードを受け取らないためで、
総合テストのステップ 9 が全サービスのログを実際に grep して 0 件であることを確認します。

#### 5. 壊してみる

**誤ったパスワード** — gateway もノードも正常に応答し、失敗するのは端末での `ct_i`
復号だけです。ノード側のログには拒否行が出ません (**ノードは成否を知らない**)。

```bash
cd projects/demo && npm run -s sign-on -- \
  --gateway http://localhost:3000 --user alice --password wrong \
  --client-id demo_client --nonce demo-bad
```

**ノードを 1 台落とす (2-of-3 で継続)** — gateway の 2 行目に除外が出ます。

```bash
docker compose stop node3
# もう一度ログイン → 成功。gateway 列に
#   round1 (D,E)×2 (node3 unreachable, excluded) → round2 …
```

**2 台目も落とす (閾値割れで失敗)**

```bash
docker compose stop node2
# ログイン → 失敗。gateway /health は 503 / status=degraded
curl -s http://localhost:3000/health | head -c 200

docker compose start node2 node3   # 復旧 (gateway の再起動は不要)
```

#### 6. 色を消す

デモログの色は各イメージが `FORCE_COLOR=1` を既定にしています (`docker compose logs` は
TTY にならないため)。色を消すときは `FORCE_COLOR=0` を使ってください (`NO_COLOR` でも
消えますが、Node 本体が警告を出すのでデモではノイズになります)。

ブラウザ役 CLI はホストのプロセスなので、そのまま環境変数で消せます。

```bash
cd projects/demo && FORCE_COLOR=0 npm run -s sign-on -- \
  --gateway http://localhost:3000 --user alice --password password123 \
  --client-id demo_client --nonce demo-plain
```

コンテナ側は `docker-compose.yml` に `FORCE_COLOR` の受け渡しが無いので、
`docker-compose.override.yml` を置くか、貼り付け用にログから ANSI を落とします。

```yaml
# docker-compose.override.yml
services:
  node1:   { environment: { FORCE_COLOR: "0" } }
  node2:   { environment: { FORCE_COLOR: "0" } }
  node3:   { environment: { FORCE_COLOR: "0" } }
  gateway: { environment: { FORCE_COLOR: "0" } }
  rp:      { environment: { FORCE_COLOR: "0" } }
```

```bash
docker compose logs --no-log-prefix gateway | sed $'s/\033\\[[0-9;]*[a-zA-Z]//g'
```

`DEMO_LOG=0` を同じ要領で渡すと、デモログ自体が止まり運用ログだけになります。

### 各コンポーネントの単体テスト

コンテナ分割前の単一プロセス版の参照実装は、コミット `ba20f512` 時点の `src/` /
`tests/` にあります（本リポジトリの現行状態からは削除済み）。分割後は各コンポーネント
ディレクトリがそれぞれ独立して依存解決・テストを行います。

```bash
cd projects/dealer  && npm ci && npm test
cd projects/node    && npm ci && npm test
cd projects/gateway && npm ci && npm test
cd projects/rp      && npm ci && npm test
```

### エンドポイント一覧（compose 起動後）

#### 実ユースケースフロー（一本道）

| 順 | URL | 役割 |
|:--:|:--|:--|
| 1 | [http://localhost:3001/](http://localhost:3001/) | 第三者サービス (ZK-App Portal) のトップ。「PASTA IdP でログイン」ボタン |
| 2 | [http://localhost:3000/authorize?...](http://localhost:3000/authorize?client_id=demo_client&redirect_uri=http://localhost:3001/callback&response_type=id_token&response_mode=form_post&scope=openid&nonce=n) | OAuth 認可エンドポイント。即座に `/demo` へリダイレクト |
| 3 | [http://localhost:3000/demo](http://localhost:3000/demo) | PASTA 分散 IdP ログイン・同意・FROST 署名アニメーション |
| 4 | [http://localhost:3001/callback](http://localhost:3001/callback) | RP コールバック。`id_token` を受信・Ed25519 検証・クレーム表示 |

#### その他エンドポイント

| URL | 役割 |
|:--|:--|
| [http://localhost:3000/.well-known/openid-configuration](http://localhost:3000/.well-known/openid-configuration) | OIDC Discovery Document |
| [http://localhost:3000/jwks.json](http://localhost:3000/jwks.json) | グループ公開鍵 (Ed25519 JWK Set) |
| [http://localhost:3000/api/pasta/sign-on](http://localhost:3000/api/pasta/sign-on) | ブラインド値 A を受け取り、ノード群に中継して暗号化シェアを返す |
| [http://localhost:3000/api/pasta/refresh](http://localhost:3000/api/pasta/refresh) | RFC 9700 sender-constrained リフレッシュ |
| [http://localhost:3000/health](http://localhost:3000/health) | gateway から見たノード群の健全性 |
| [http://localhost:3001/health](http://localhost:3001/health) | rp のヘルスチェック |

---

## 8. ドキュメント一覧

- [`docs/container-split.md`](./docs/container-split.md): コンテナ分割の設計契約（`dealer` / `node` / `gateway` / `rp` の責務、ポート、環境変数、HTTP API、compose と総合テストの仕様）
- [`docs/specification.md`](./docs/specification.md): アーキテクチャ仕様書（ホワイトボード穴①〜⑦の解決仕様、API、データスキーマ）
- [`docs/whiteboard-gaps.md`](./docs/whiteboard-gaps.md): 設計の原点となったホワイトボード検討記録
- [`docs/readme.md`](./docs/readme.md): 根本課題（なりすまし・権限集中）の論理的解説
- [`docs/status.md`](./docs/status.md): 学会投稿先（SSR, RWC, IWSEC等）の分析と残論点
- [`docs/refresh-token.md`](./docs/refresh-token.md): OAuth仕様を壊さないリフレッシュトークン設計
- [`docs/prior-art.md`](./docs/prior-art.md): 先行研究 (PASTA / PESTO) サーベイ
- [`docs/implementation.md`](./docs/implementation.md): PASTA 暗号束縛の解説

デモ・検証用のスクリプト:

- [`scripts/integration-test.sh`](./scripts/integration-test.sh): compose 構成の総合テスト (120 項目、Node.js 20 以上が必要)
- [`scripts/demo-tmux.sh`](./scripts/demo-tmux.sh): node ×3 / gateway / rp のログを tmux で 5 列に並べ、6 つ目にブラウザ役 CLI を用意する
- [`projects/demo/cli/sign-on.ts`](./projects/demo/cli/sign-on.ts): ブラウザ役 CLI スタンドイン (ブラウザと同じ SDK を Node で実行)

---

## ライセンス
MIT License
