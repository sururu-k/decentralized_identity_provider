# 分散IdP（PASTA方式）OAuth 2.0 / OIDC 認可デモ

本ディレクトリには、PASTA曲線（Pallas & Vesta）とMPC（Multi-Party Computation）、TOPRF、FROSTしきい値署名（2-of-3）を用いた分散型アイデンティティプロバイダ（Decentralized IdP）のOAuth 2.0 / OpenID Connect ログイン・同意画面デモが含まれています。

---

## 🚀 起動方法

外部ビルドツール（Node.js, Rust等）は不要で、Webブラウザで直接開くだけで動作します。

### 方法 1: ブラウザで直接開く (macOS)
```bash
open demo/index.html
```

### 方法 2: 簡易HTTPサーバーで起動する場合
```bash
# Python 3 の場合
python3 -m http.server 8080 --directory demo
# ブラウザで http://localhost:8080 を開く
```

---

## 🎨 画面構成と機能

本デモは、OAuth 2.0 / OIDC の仕様に完全に沿った4つのステップで構成されています。

### 1. ログイン画面 (`Step 1`)
- **クライアント（RP）情報バナー**:
  - 対象サービス: `ZK-App Portal` (https://portal.zk-app.example)
  - `client_id`, `response_type=code` 等のOIDC標準パラメータを表示
- **PASTA方式 セキュリティバッジ**:
  - パスワードや秘密鍵が単一サーバーに存在しない旨を説明
- **ワンクリック・デモアカウント切り替え**:
  - Alice Nakamoto (`alice@zk-auth.network`)
  - Bob Vance (`bob.validator@enterprise.io`)
- **ブラインド入力**: TOPRFによりクライアント側でマスクされるパスワード入力

### 2. 認可同意画面 (Consent Screen / `Step 2`)
- **要求スコープ (Scopes) の一覧とトグル**:
  - `openid` (必須: ユーザーID `sub` の発行)
  - `profile` (氏名、ユーザー名の開示)
  - `email` (メールアドレスの開示)
  - `pasta:zk_claims` (分散IdP PASTA特有の暗号化コミットメント)
  - `offline_access` (リフレッシュトークン)
- **認可・キャンセルボタン**:
  - キャンセル時は `error=access_denied` をシミュレート
  - 同意時は分散MPCしきい値署名ステップへ進行

### 3. 分散ノード 暗号化・署名シェア収集 (`Step 3`)
- **分散ノード 3台のステータスカード**:
  - Node 1: Tokyo 🇯🇵 (`ap-northeast-1`)
  - Node 2: Frankfurt 🇩🇪 (`eu-central-1`)
  - Node 3: Oregon 🇺🇸 (`us-west-2`)
- **リアルタイム処理プログレス**:
  - 1. クライアント側ブラインディング ($P' = r \cdot P$)
  - 2. 各ノードへのTOPRF評価クエリ送信 & Beaver Triple乗算
  - 3. 2-of-3 しきい値到達によるクォーラム達成
  - 4. ラグランジュ補間による FROST EdDSA 署名シェアの合成
  - 5. クライアント側でのアンブラインド ($r^{-1}$)
- **リアルタイム P2P 暗号化ターミナルログ**: 演算詳細とレイテンシを可視化

### 4. 完了 & JWT Claims ビュアー (`Step 4`)
- **JWTトークン表示 (jwt.io風カラーリング)**:
  - Header（赤）, Payload（紫）, Signature（水色）
  - ワンクリックコピー機能
- **デコード済み Claims JSON ビュアー**:
  - `iss`, `sub`, `aud`, `exp`, `amr: ["mpc_toprf", "frost_threshold_eddsa"]`, `curve: "Pallas/Vesta"` などのクレーム確認
- **RP側受取シミュレーションモーダル**:
  - リダイレクトURIへの認可コード付与、RP側でのトークン検証成功ダイアログ

---

## 🛠 技術ポイント

1. **ゼロ知識・平文漏洩耐性 (TOPRF)**:
   IdPノードはユーザーの平文パスワードを知ることなく認証を行います。
2. **単一障害点のない署名秘密鍵 (FROST 2-of-3)**:
   IdP秘密鍵は3台に分散シェアされ、単一サーバーのハッキングや運営者によるトークン偽造・ユーザー追跡を防止します。
3. **高効率暗号曲線 (PASTA Curve)**:
   Halo2等で実績のある Pallas & Vesta 曲線を採用し、ブラウザおよびノード間での高速MPC演算を実現しています。
