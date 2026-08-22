# 進捗と残論点 (2026-08-22)

[Issue #81](https://github.com/zk-tokyo/advanced-cryptography-2026/issues/81) について、
**今回どこまで作ったか** と **何が残っているか**。

---

## 図解

### 方針の変化 — 議論での到達点 → PASTA

```mermaid
graph LR
    subgraph Before["議論での到達点"]
        direction TB
        b1["サーバがパスワードを検証"]
        b2["検証が通ったら署名シェアを出す"]
        b3["MPC 回路で束縛<br>z_i にマスク d·r を加算"]
        b1 --> b2 --> b3
    end

    subgraph After["PASTA（今回採用）"]
        direction TB
        a1["サーバは検証しない"]
        a2["署名シェアを無条件に生成し<br>h_i で暗号化して返す"]
        a3["クライアントが復号できるか<br>= 認証の成否"]
        a1 --> a2 --> a3
    end

    Before ==>|"4ラウンド → 2ラウンド<br>MPC 回路が不要に<br>Beaver triple の出番が消えた"| After
```

### 到達度 — 何ができて何が残っているか

```mermaid
graph TB
    subgraph Done["✅ 実装済み・テスト済み"]
        direction LR
        d1["認証<br>2HashTDH 閾値 OPRF"]
        d2["認証と署名の束縛<br>PASTA 暗号化方式"]
        d3["閾値署名<br>FROST → 標準 Ed25519"]
        d4["決定的な JWT<br>alg: EdDSA"]
    end

    subgraph Half["🔺 途中まで"]
        direction LR
        h1["DPoP 束縛<br>cnf.jkt を入れるまで<br>証明の検証は未実装"]
        h2["レート制限<br>構造は得た<br>試行回数の制限は未実装"]
    end

    subgraph Todo["❌ 未着手"]
        direction LR
        t1["ゲートウェイ<br>OAuth / ネットワーク層"]
        t2["DKG<br>今は trusted dealer"]
        t3["結託耐性<br>PESTO の PSS"]
    end

    subgraph Open["🚨 未解決 — 要議論"]
        direction LR
        o1["リフレッシュトークン<br>設計は済んだが実装は未"]
        o2["アカウント回復<br>別の鍵生成経路を足す方針"]
    end

    Done --> Half --> Todo
    Open -.->|"設計をひっくり返す可能性"| Done
```

### OAuth / OIDC の形式は保つ

**RP から見える形式は標準の OIDC のまま変えない。** 分散はゲートウェイの内側に隠す。
Issue の「受け渡すパラメータは変えず、既存の集権的 IdP をそのまま置き換える」という前提。

```mermaid
graph LR
    RP(["RP<br>（既存のサービス）"])

    subgraph Standard["RP から見える範囲 — 標準の OIDC のまま"]
        direction TB
        e1["/.well-known/openid-configuration"]
        e2["/authorize<br>client_id, redirect_uri,<br>response_type, scope, state"]
        e3["/token<br>grant_type, code"]
        e4["/jwks.json<br>グループ公開鍵 1 本"]
        e5["アクセストークン<br>alg: EdDSA の JWT"]
    end

    subgraph Hidden["この内側に分散が隠れる"]
        direction TB
        gw["ゲートウェイ<br>暗号学的に無権限<br>掌握されても署名は出せない"]
        n1["Node 1"]
        n2["Node 2"]
        n3["Node 3"]
        gw --- n1
        gw --- n2
        gw --- n3
    end

    RP <-->|"パラメータは一切変えない"| Standard
    Standard --> Hidden
    e5 -.->|"閾値署名であることを<br>RP は知らなくてよい"| RP
```

| RP から見えるもの | 状態 |
|:--|:--|
| **アクセストークン（`alg: EdDSA` の JWT）** | ✅ **実装済**。標準の Ed25519 検証器で通ることを確認済み |
| `/.well-known/openid-configuration` | ❌ 未実装 |
| `/authorize`（client_id, redirect_uri, response_type, scope, state） | ❌ 未実装 |
| `/token`（grant_type, code） | ❌ 未実装 |
| `/jwks.json`（グループ公開鍵 1 本） | ❌ 未実装 |

**いちばん互換性が問われる「トークンそのもの」は既に標準形式で出せている。**
クレームも `iss` / `sub` / `aud` / `iat` / `exp` / `jti` / `cnf` と標準のものだけで構成してある。
残っているのはエンドポイントの実装で、これは論点E（ゲートウェイ）に含まれる。

> **論点G（リフレッシュトークン）についても、OAuth を壊さずに実装できる見込みが立った。**
> リフレッシュトークンは仕様上 opaque で、RFC 9449 §5 が「束縛の実装詳細は認可サーバの裁量」と
> 明記しているため、分散 IdP 固有の仕組みを入れる余地が標準の側に空いている。
> 詳細 → [refresh-token.md](./refresh-token.md)

### 塞いだなりすまし経路

テスト 28 本が、それぞれどの攻撃経路に対応しているか。

```mermaid
graph LR
    A(["なりすましを狙う攻撃者"])

    A --> P1["署名鍵を盗む"]
    A --> P2["認証を飛ばして<br>署名だけ要求する"]
    A --> P3["ノードを 1 台掌握する"]
    A --> P4["sub を他人に<br>差し替える"]
    A --> P5["署名シェアを<br>別セッションに流用"]
    A --> P6["発行済みトークンを盗む"]

    P1 --> R1["どこにも鍵が揃っていない<br>閾値署名 t-of-n"]
    P2 --> R2["復号できない<br>PASTA の束縛"]
    P3 --> R3["他ノードの h_j が手に入らない<br>h は誰にも渡らない"]
    P4 --> R4["各ノードが自分のレコードから<br>ペイロードを構築する"]
    P5 --> R5["AEAD の AAD に<br>署名対象を入れてある"]
    P6 --> R6["DPoP 束縛<br>cnf.jkt"]

    R1 --> OK(["✅ 全経路をテストで実証"])
    R2 --> OK
    R3 --> OK
    R4 --> OK
    R5 --> OK
    R6 --> OK
```

### 残論点の依存関係と優先順位

```mermaid
graph TD
    Now(["現在地<br>3 ノード t=2 で JWT 発行まで動く"])

    Now --> G["🔺 リフレッシュトークン<br>OAuth を壊さず実装可能と結論<br>実装はこれから"]
    Now --> H["🚨 アカウント回復<br>マイナ/JPKI 等の<br>別の鍵生成経路を足す方針"]

    G --> Decide{"設計の方向が決まる"}
    H --> Decide

    Decide --> DKG["DKG を実装<br>trusted dealer を外す"]
    DKG --> Net["ネットワーク層<br>+ OAuth ゲートウェイ"]
    Net --> RP(["RP から実際に叩ける形になる"])
    RP --> PSS["PESTO の<br>proactive secret sharing"]

    G -.->|"どちらも先行研究に<br>前例が無い"| H
```

---

## 今回できたこと

### 1. 先行研究が見つかった（方針が変わった）

**[PASTA (CCS 2018)](https://eprint.iacr.org/2018/885)** が、この Issue とほぼ同一のテーマを
既に定式化・実装・証明していた。**[PESTO (EuroS&P 2020)](https://eprint.iacr.org/2019/1470)** がその改良版。

これにより、議論で到達していた「認証と署名をひとつの MPC 回路に束縛する」という方針が変わった。
PASTA の解き方は **サーバはパスワードを検証せず、署名シェアをパスワード由来の鍵で暗号化して返す**。
正しいパスワードを持つクライアントだけが復号して結合できる。
「認証が通らないと署名が発火しない」を、発火の制御ではなく **復号の可否** で実現している。

結果として **MPC 回路が不要になり、既存の Beaver triple 実装は今回の構成では使っていない**。

詳細 → [prior-art.md](./prior-art.md)

### 2. 動く PoC ができた

3 ノード / 閾値 2 で、パスワード認証からアクセストークン発行までが通る。

```sh
cargo test --lib --test pasta_integration        # 28 テスト
cargo run --bin pasta_demo | python3 scripts/verify_token.py
```

**いちばん重要な確認結果:**
どのノードも署名鍵を持っていないのに、出てきた JWT が **標準の Ed25519 検証器で通る**。
検証は Python の `cryptography` (OpenSSL 系) と PyNaCl (libsodium) で行っており、
IdP 側の実装を一切共有していない。つまり RP は閾値署名であることを知る必要がない。

これが「既存の集権的 IdP をそのまま置き換える」という目標に対する答えになる。

詳細 → [implementation.md](./implementation.md)

---

## 論点ごとの到達度

論点 A〜J の現在地。

| # | 論点 | 状態 | 中身 |
|:--|:--|:--|:--|
| A | 認証方式 | ✅ 実装済 | 2HashTDH 閾値 OPRF。TOPRF 鍵はクライアントごとに生成 |
| B | 認証と署名の束縛 | ✅ 実装済 | **PASTA 方式に変更。** MPC 回路は不要になった |
| C | 閾値署名 | ✅ 実装済 | FROST 方式の閾値 Schnorr → 標準 Ed25519 署名 |
| D | ペイロードの決定性 | ✅ 実装済 | 落とし穴を1つ発見（後述） |
| E | ゲートウェイ / OAuth 互換 | ❌ 未実装 | サーバはプロセス内の構造体。ネットワーク層と OAuth 層が無い |
| F | トークン束縛 (DPoP) | 🔺 半分 | `cnf.jkt` をペイロードに入れるところまで。DPoP 証明の検証は未実装 |
| G | **リフレッシュトークン** | 🔺 **設計済** | OAuth を壊さず実装可能と結論 → [refresh-token.md](./refresh-token.md) |
| H | **アカウント回復** | ❌ **未解決** | 分散環境に「運営に問い合わせ」窓口が無い |
| I | レート制限 | 🔺 構造のみ | TOPRF がオンライン攻撃を強制する性質は得た。試行回数の制限は未実装 |
| J | 結託耐性 | ❌ 未実装 | PESTO の proactive secret sharing に答えがある |
| — | DKG（分散鍵生成） | ❌ 未実装 | 署名鍵を trusted dealer で作っている。生成時点では鍵が揃ってしまう |

---

## 実装して分かったこと

設計段階では見えていなかった点が3つあり、いずれも議論に戻す価値がある。
内容は [implementation.md](./implementation.md#実装して分かったこと) に書いた。

1. **時刻の量子化だけでは決定性は得られない** — バケット境界をまたぐと 29 秒差でもズレる
2. **FROST の t-of-n はセッション開始後の脱落耐性ではない** — 可用性設計に影響する
3. **`frost-ed25519` クレートが使えなかった** — dalek のバージョンが噛み合わず自前実装した

---

## 残論点の優先順位

### 論点G: リフレッシュトークン → 方針が決まった

**OAuth のプロトコルを壊さずに実装できる**と結論した。詳細は [refresh-token.md](./refresh-token.md)。

決め手は3点。リフレッシュトークンは仕様上 **opaque** で中身の規定が無いこと、
RFC 9449 §5 が **「束縛の実装詳細は認可サーバの裁量」** と明記していること、
リクエストの形（`grant_type=refresh_token` + `DPoP` ヘッダ）が標準のままであること。

設計は PASTA の構造をそのまま流用し、**「解錠鍵の供給源」だけを差し替える**。

| フェーズ | 解錠鍵の供給源 | 各ノードが自分で検証するもの |
|:--|:--|:--|
| sign-on | パスワード → TOPRF → `h_i` | （検証しない。復号可否が認証） |
| refresh | sign-on 時に配った `rs_i` | DPoP 証明の署名 |
| recovery | マイナ/JPKI 等の別経路 | 署名 + 証明書チェーン |

DPoP 証明の検証はただの公開鍵署名検証なので閾値プロトコルは不要で、
「外部の認証OKフラグを信用しない」原則も保たれる。

ただし正直に言うと、**refresh は定義上 sign-on より弱い**（知識 → 所持）。
これは OAuth 自体が受け入れているトレードオフで、緩和はローテーションと短命化。
また **PbTA 系で refresh を扱った先行研究が無く、この設計に証明は無い**。

### 論点H: アカウント回復 → 後回し

**別の鍵生成経路（マイナンバーカード/JPKI 等）を足す**方針。
JPKI の署名用証明書は各ノードが独立に検証できるので、上の表のとおり refresh と同じ形に収まる。

外せない条件が1つだけある。

> **回復も t-of-n にすること。**
> 1台が単独で回復を発火できると、その1台の掌握 = アカウント乗っ取りになる。

なお [PAS-TA-U (SPACE'20)](https://eprint.iacr.org/2020/1544) は PASTA に**パスワード更新**を
足した研究だが、旧パスワードを知っている前提なので**忘却からの回復には使えない**。

### 次: 実装を実用に近づけるもの

1. **DKG** — 今は trusted dealer で鍵を作っており、生成時点で鍵が揃ってしまう
2. **ネットワーク層 + OAuth ゲートウェイ（論点E）** — RP から見て標準の OIDC に見せる部分
3. **DPoP 証明の検証（論点F）** — 今は `cnf.jkt` を入れるだけ
4. **レート制限（論点I）** — オンライン辞書攻撃対策の実装

### 最後: 論点 J（結託耐性）

PESTO の proactive secret sharing。Issue でも「一番最後に考えたほうがいい」としていた通り。

---

## 次にやること

1. 論点 G・H を議論して方向を決める
2. DKG を実装して trusted dealer を外す
3. ネットワーク層と OAuth ゲートウェイを載せて、RP から実際に叩ける形にする

## ドキュメント

| ファイル | 内容 |
|:--|:--|
| [readme.md](./readme.md) | 議論の整理と背景 |
| [prior-art.md](./prior-art.md) | 先行研究 (PASTA / PESTO) の調査 |
| [implementation.md](./implementation.md) | PoC の実装解説 |
| このファイル | 進捗と残論点 |
