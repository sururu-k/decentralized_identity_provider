//! PASTA 方式の分散 IdP が、Issue #81 の脅威モデルを実際に満たすことの実証。
//!
//! 各テストが「なりすましのどの経路を塞いでいるか」に対応している。

use beaver_triple_mpc::pasta::jwt;
use beaver_triple_mpc::pasta::protocol::{
    self, Error, IdpMetadata, Server, SignOnResponse,
};
use beaver_triple_mpc::pasta::tsign::{self, Commitment};

const N: u16 = 3;
const T: u16 = 2;

const USERNAME: &str = "alice";
const PASSWORD: &[u8] = b"correct horse battery staple";
const DPOP_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

fn setup() -> (Vec<Server>, IdpMetadata) {
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

    protocol::register(&mut servers, USERNAME, PASSWORD, T);

    (servers, metadata)
}

/// 1 回の sign-on を最後まで走らせる。`subset` が応答するサーバの添字。
fn sign_on(
    servers: &mut [Server],
    metadata: &IdpMetadata,
    password: &[u8],
    subset: &[usize],
    session: [u8; 16],
) -> Result<String, Error> {
    let (responses, pending) = collect_responses(servers, password, subset, session);
    protocol::finish_sign_on(&pending, password, metadata, &responses, T)
}

/// Round 1 と Round 2 を回してサーバの生レスポンスを得る。
fn collect_responses(
    servers: &mut [Server],
    password: &[u8],
    subset: &[usize],
    session: [u8; 16],
) -> (Vec<SignOnResponse>, protocol::PendingSignOn) {
    let commitments: Vec<Commitment> = subset
        .iter()
        .map(|&i| servers[i].preprocess(session))
        .collect();

    let (pending, request) =
        protocol::begin_sign_on(USERNAME, password, DPOP_JKT, session, commitments);

    let responses = subset
        .iter()
        .map(|&i| {
            servers[i]
                .sign_on(&request)
                .expect("サーバはパスワードを検証しないので常に応答する")
        })
        .collect();

    (responses, pending)
}

fn decode_payload(token: &str) -> String {
    let payload = token.split('.').nth(1).expect("JWT は 3 セグメント");
    String::from_utf8(jwt::decode_base64url(payload).expect("base64url")).expect("UTF-8")
}

// ---------------------------------------------------------------------------
// 正常系
// ---------------------------------------------------------------------------

/// 正しいパスワードなら、RP が標準の Ed25519 検証で通せるトークンが出る。
#[test]
fn correct_password_yields_token_verifiable_by_rp() {
    let (mut servers, metadata) = setup();

    let token = sign_on(&mut servers, &metadata, PASSWORD, &[0, 1], [7u8; 16])
        .expect("正しいパスワードなのでトークンが出るはず");

    assert_eq!(token.split('.').count(), 3, "JWT は 3 セグメント");
    assert!(
        protocol::verify_token(&metadata, &token),
        "グループ公開鍵で検証できること"
    );
}

/// どの t 台の組み合わせでも、同じグループ公開鍵で検証できるトークンになる。
#[test]
fn any_quorum_yields_valid_token() {
    let (mut servers, metadata) = setup();

    for (i, subset) in [[0, 1], [1, 2], [0, 2]].iter().enumerate() {
        let session = [i as u8; 16];
        let token = sign_on(&mut servers, &metadata, PASSWORD, subset, session)
            .expect("どの quorum でも成立する");
        assert!(protocol::verify_token(&metadata, &token), "subset {subset:?}");
    }
}

/// ヘッダは `alg: EdDSA`。RP は閾値署名であることを知る必要がない。
#[test]
fn header_declares_standard_eddsa() {
    let (mut servers, metadata) = setup();
    let token = sign_on(&mut servers, &metadata, PASSWORD, &[0, 1], [3u8; 16]).unwrap();

    let header = token.split('.').next().unwrap();
    let header = String::from_utf8(jwt::decode_base64url(header).unwrap()).unwrap();

    assert_eq!(
        header,
        r#"{"alg":"EdDSA","typ":"JWT","kid":"group-key-1"}"#
    );
}

// ---------------------------------------------------------------------------
// PASTA の束縛: サーバは検証せず、復号可否が認証になる
// ---------------------------------------------------------------------------

/// **サーバはパスワードを検証しない。** 間違ったパスワードでも署名シェアを生成して返す。
/// それでもトークンにならないのは、クライアントが復号できないから。
#[test]
fn servers_emit_shares_without_verifying_password() {
    let (mut servers, _) = setup();

    let (responses, _) =
        collect_responses(&mut servers, b"wrong password", &[0, 1], [1u8; 16]);

    assert_eq!(responses.len(), 2, "サーバは拒否せず応答している");
    assert!(
        responses.iter().all(|r| !r.ciphertext.is_empty()),
        "署名シェアは実際に生成され、暗号化されて返っている"
    );
}

/// 間違ったパスワードでは h が違うので復号に失敗し、トークンにならない。
#[test]
fn wrong_password_yields_no_token() {
    let (mut servers, metadata) = setup();

    let result = sign_on(&mut servers, &metadata, b"wrong password", &[0, 1], [2u8; 16]);

    assert_eq!(result.unwrap_err(), Error::AuthenticationFailed);
}

/// t 未満しか応答が無ければトークンは作れない。
#[test]
fn below_threshold_yields_no_token() {
    let (mut servers, metadata) = setup();

    let (responses, pending) = collect_responses(&mut servers, PASSWORD, &[0], [4u8; 16]);
    let result = protocol::finish_sign_on(&pending, PASSWORD, &metadata, &responses, T);

    assert_eq!(result.unwrap_err(), Error::NotEnoughShares);
}

// ---------------------------------------------------------------------------
// なりすまし耐性
// ---------------------------------------------------------------------------

/// **1 台掌握してもなりすませない。**
///
/// 攻撃者はサーバ 0 の署名鍵シェア・TOPRF 鍵シェア・h_0 を全て得ているが、
/// パスワードを知らない限り他サーバの暗号文を開けない（client impersonation 対策）。
#[test]
fn breaching_one_server_does_not_allow_forgery() {
    let (mut servers, metadata) = setup();

    let (record, signing_share) = servers[0].breach(USERNAME).expect("侵害できる");
    assert_eq!(signing_share.id, servers[0].id);
    let _stolen_h0 = record.server_key;

    // 盗んだ情報を持ったまま、パスワードを推測して sign-on を試みる
    let result = sign_on(&mut servers, &metadata, b"guessed password", &[0, 1], [5u8; 16]);

    assert_eq!(
        result.unwrap_err(),
        Error::AuthenticationFailed,
        "h_0 を持っていてもサーバ 1 の暗号文は開けない"
    );
}

/// **署名シェアは別セッションに流用できない。**
///
/// AEAD の AAD に署名対象を入れてあるので、セッション A のレスポンスを
/// セッション B に持ち込んでも復号が通らない。
#[test]
fn shares_cannot_be_replayed_across_sessions() {
    let (mut servers, metadata) = setup();

    // セッション A: 正しいパスワードで応答を集める
    let (responses_a, _) = collect_responses(&mut servers, PASSWORD, &[0, 1], [10u8; 16]);

    // セッション B を別途開始し、A のレスポンスを流し込む
    let commitments: Vec<Commitment> = [0, 1]
        .iter()
        .map(|&i| servers[i].preprocess([11u8; 16]))
        .collect();
    let (pending_b, _) =
        protocol::begin_sign_on(USERNAME, PASSWORD, DPOP_JKT, [11u8; 16], commitments);

    let result = protocol::finish_sign_on(&pending_b, PASSWORD, &metadata, &responses_a, T);

    assert_eq!(result.unwrap_err(), Error::AuthenticationFailed);
}

/// **前処理したノンスは使い捨て。** 同じセッションで 2 度署名させられない。
#[test]
fn preprocessed_nonce_is_single_use() {
    let (mut servers, _) = setup();
    let session = [12u8; 16];

    let commitments: Vec<Commitment> = [0, 1]
        .iter()
        .map(|&i| servers[i].preprocess(session))
        .collect();
    let (_, request) =
        protocol::begin_sign_on(USERNAME, PASSWORD, DPOP_JKT, session, commitments);

    assert!(servers[0].sign_on(&request).is_ok());
    assert_eq!(
        servers[0].sign_on(&request).unwrap_err(),
        Error::NoPreprocessedNonce,
        "ノンス再利用は Schnorr の鍵漏洩に直結するので必ず弾く"
    );
}

// ---------------------------------------------------------------------------
// ペイロード構築の原則
// ---------------------------------------------------------------------------

/// **`sub` はサーバが自分のレコードから決める。** クライアントは指定できない。
///
/// 論点B の「渡されたペイロードに署名してはいけない」原則の実証。
/// `SignOnRequest` にはそもそもペイロードを載せる場所が無い。
#[test]
fn subject_comes_from_server_record() {
    let (mut servers, metadata) = setup();
    let token = sign_on(&mut servers, &metadata, PASSWORD, &[0, 1], [6u8; 16]).unwrap();

    let payload = decode_payload(&token);

    assert!(payload.contains(r#""sub":"alice""#), "payload = {payload}");
    assert!(payload.contains(r#""iss":"https://idp.example""#));
    assert!(payload.contains(r#""aud":"https://rp.example""#));
}

/// **トークンは DPoP 鍵に束縛される。** 盗んだだけでは使えない (RFC 9449)。
#[test]
fn token_is_bound_to_dpop_key() {
    let (mut servers, metadata) = setup();
    let token = sign_on(&mut servers, &metadata, PASSWORD, &[0, 1], [8u8; 16]).unwrap();

    let payload = decode_payload(&token);

    assert!(
        payload.contains(&format!(r#""cnf":{{"jkt":"{DPOP_JKT}"}}"#)),
        "payload = {payload}"
    );
}

/// 全サーバが **バイト単位で同一の** ペイロードに署名していることの実証。
///
/// 各サーバは自分のレコードから独立にペイロードを構築している。1 台でも 1 バイト違えば
/// 集約した署名は検証を通らないので、**通ること自体が全ノード一致の証拠**になる（論点D）。
#[test]
fn all_servers_sign_byte_identical_payload() {
    let (mut servers, metadata) = setup();

    let (responses, pending) = collect_responses(&mut servers, PASSWORD, &[0, 1, 2], [9u8; 16]);
    assert_eq!(responses.len(), 3);

    let token = protocol::finish_sign_on(&pending, PASSWORD, &metadata, &responses, T)
        .expect("3 台全員のシェアが揃っている");
    assert!(protocol::verify_token(&metadata, &token));
}

/// ⚠️ **FROST では round 1 でコミットした参加者は全員 round 2 に出る必要がある。**
///
/// R と λ_i は署名パッケージに載った参加者集合全体で決まるので、部分集合では成立しない。
/// t-of-n が与えるのは「どの quorum を選ぶか」の自由であって、
/// **セッション開始後の脱落耐性ではない**。1 台落ちたらセッションごとやり直す。
#[test]
fn commitment_set_must_be_complete() {
    let (mut servers, metadata) = setup();

    // 3 台でコミットしたのに 2 枚しか集約しない
    let (responses, pending) = collect_responses(&mut servers, PASSWORD, &[0, 1, 2], [14u8; 16]);
    let result = protocol::finish_sign_on(&pending, PASSWORD, &metadata, &responses[0..2], T);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidSignature,
        "閾値 t は満たしていても、コミットメント集合と一致しなければ署名は成立しない"
    );
}

/// 改竄されたトークンは検証で落ちる。
#[test]
fn tampered_token_is_rejected() {
    let (mut servers, metadata) = setup();
    let token = sign_on(&mut servers, &metadata, PASSWORD, &[0, 1], [13u8; 16]).unwrap();

    let mut parts: Vec<&str> = token.split('.').collect();
    let forged_payload = jwt::signing_input("{}", r#"{"sub":"admin"}"#);
    let forged_payload = forged_payload.split('.').nth(1).unwrap().to_string();
    parts[1] = &forged_payload;

    assert!(!protocol::verify_token(&metadata, &parts.join(".")));
}
