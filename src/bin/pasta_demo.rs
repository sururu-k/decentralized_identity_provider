//! PASTA 方式の分散 IdP のデモ。
//!
//! 3 ノード (t=2) を立て、パスワード認証からアクセストークン発行までを 1 回通す。
//! 出力した JWT とグループ公開鍵は、標準の Ed25519 検証器で検証できる。
//!
//! ```text
//! cargo run --bin pasta_demo
//! ```

use beaver_triple_mpc::pasta::protocol::{self, IdpMetadata, Server};
use beaver_triple_mpc::pasta::tsign;

const N: u16 = 3;
const T: u16 = 2;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // --- セットアップ: 署名鍵を 3 台に分散する。マスター鍵はどこにも存在しない ---
    let (signing_shares, public_key) = tsign::generate_key(N, T);

    let metadata = IdpMetadata {
        issuer: "https://idp.example".to_string(),
        audience: "https://rp.example".to_string(),
        kid: "group-key-1".to_string(),
        public_key,
    };

    let mut servers: Vec<Server> = signing_shares
        .iter()
        .map(|share| Server::new(share.id, *share, metadata.clone()))
        .collect();

    // --- 登録: TOPRF 鍵はこのクライアント専用。h_i だけが各サーバに渡る ---
    protocol::register(&mut servers, "alice", b"correct horse battery staple", T);

    // --- Round 1 (前処理可能): 2 台がコミットメントを出す ---
    let session = [42u8; 16];
    let quorum = [0usize, 1];
    let commitments: Vec<_> = quorum
        .iter()
        .map(|&i| servers[i].preprocess(session))
        .collect();

    // --- Round 2: 目隠ししたパスワードを送り、暗号化された署名シェアを受け取る ---
    let dpop_jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let (pending, request) = protocol::begin_sign_on(
        "alice",
        b"correct horse battery staple",
        dpop_jkt,
        session,
        commitments,
    );

    let responses: Vec<_> = quorum
        .iter()
        .map(|&i| servers[i].sign_on(&request).expect("サーバは検証せず応答する"))
        .collect();

    // --- クライアント側で復号・集約。ここで初めて「認証」が起きる ---
    let token = protocol::finish_sign_on(
        &pending,
        b"correct horse battery staple",
        &metadata,
        &responses,
        T,
    )
    .expect("正しいパスワード");

    println!("PUBKEY {}", hex(&metadata.public_key.to_bytes()));
    println!("TOKEN {token}");

    // --- 間違ったパスワードでは、サーバが応答していてもトークンにならない ---
    let session2 = [43u8; 16];
    let commitments2: Vec<_> = quorum
        .iter()
        .map(|&i| servers[i].preprocess(session2))
        .collect();
    let (pending2, request2) =
        protocol::begin_sign_on("alice", b"wrong password", dpop_jkt, session2, commitments2);
    let responses2: Vec<_> = quorum
        .iter()
        .map(|&i| servers[i].sign_on(&request2).expect("サーバは拒否しない"))
        .collect();

    let outcome = protocol::finish_sign_on(&pending2, b"wrong password", &metadata, &responses2, T);
    println!(
        "WRONG_PASSWORD servers_responded={} result={:?}",
        responses2.len(),
        outcome.expect_err("失敗するはず")
    );
}
