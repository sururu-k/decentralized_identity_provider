//! PASTA (CCS 2018) 方式の分散 IdP。登録と sign-on。
//!
//! # 束縛のからくり
//!
//! **サーバはパスワードを検証しない。** 無条件に署名シェアを生成し、それを
//! パスワード由来の鍵 h_i で暗号化して返す。正しいパスワードを持つクライアントだけが
//! 復号して t 個のシェアを結合できる。
//!
//! 「認証が通っていないと署名が発火しない」を、発火の制御ではなく **復号の可否** で
//! 実現している。おかげで署名計算を MPC 回路に押し込む必要が無い。
//!
//! # 破れないこと
//!
//! - t-1 台を掌握 → 署名シェアが足りない。かつ h_i が揃わないので復号もできない
//! - 1 台から h_i を盗む → 他サーバ分の h_j は依然として秘密（client impersonation 対策）
//! - ペイロード差し替え → 各サーバが **自分のレコードから** ペイロードを構築するので不可能

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

use super::jwt;
use super::shamir::{ParticipantId, Share};
use super::toprf::{self, Blinding};
use super::tsign::{self, Commitment, GroupPublicKey, Nonces};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnknownUser,
    /// クライアントが提案した `iat` がサーバの時計と乖離しすぎている。
    ClockSkew,
    /// この session に対する round-1 の前処理が無い。
    NoPreprocessedNonce,
    /// 復号に失敗した = パスワードが違う。
    AuthenticationFailed,
    /// 集まったシェアが閾値に届かない。
    NotEnoughShares,
    /// 集約した署名がグループ公開鍵で検証できない。
    /// round 1 のコミットメント集合と round 2 の応答が一致していない場合に起きる。
    InvalidSignature,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("システム時刻が UNIX epoch より前")
        .as_secs()
}

/// IdP 全体で共有される公開メタデータ。`/.well-known` で配るもの。
#[derive(Clone)]
pub struct IdpMetadata {
    pub issuer: String,
    pub audience: String,
    pub kid: String,
    /// JWKS で公開するグループ公開鍵。RP はこれで普通に Ed25519 検証する。
    pub public_key: GroupPublicKey,
}

/// 登録時にサーバが受け取り保存するもの。
#[derive(Clone, Copy)]
pub struct UserRecord {
    /// このクライアント専用の TOPRF 鍵のシェア。
    pub toprf_key_share: Share,
    /// h_i = H'(h, i)。h そのものはサーバに渡らない。
    pub server_key: [u8; 32],
}

pub struct Server {
    pub id: ParticipantId,
    signing_key_share: Share,
    metadata: IdpMetadata,
    users: HashMap<String, UserRecord>,
    pending: HashMap<[u8; 16], Nonces>,
}

/// Round 2 でクライアントが送るもの。**署名対象のペイロードは含まれない。**
pub struct SignOnRequest {
    pub username: String,
    /// 目隠しされたパスワード。
    pub blinded: RistrettoPoint,
    /// DPoP 公開鍵の thumbprint。トークンの持ち主を束縛する。
    pub cnf_jkt: String,
    pub session_nonce: [u8; 16],
    /// クライアントが提案する `iat`。サーバが自分の時計と照合する。
    pub iat: u64,
    pub commitments: Vec<Commitment>,
}

/// Round 2 でサーバが返すもの。
#[derive(Debug)]
pub struct SignOnResponse {
    pub id: ParticipantId,
    /// TOPRF の部分評価 b_i = [k_i]·a
    pub toprf_partial: RistrettoPoint,
    /// h_i で暗号化された署名シェア。
    pub ciphertext: Vec<u8>,
}

/// AEAD の nonce をセッションとサーバ ID から決定的に導出する。伝送不要。
fn aead_nonce(session_nonce: &[u8; 16], id: ParticipantId) -> [u8; 12] {
    let mut hasher = Sha512::new();
    hasher.update(b"PASTA-AEAD-NONCE");
    hasher.update(session_nonce);
    hasher.update(id.to_le_bytes());

    let mut out = [0u8; 12];
    out.copy_from_slice(&hasher.finalize()[..12]);
    out
}

/// ペイロードを決定的に構築する。**サーバもクライアントも同じ関数を通る。**
fn build_signing_input(
    metadata: &IdpMetadata,
    username: &str,
    cnf_jkt: &str,
    session_nonce: &[u8; 16],
    iat_quantized: u64,
) -> String {
    let jti = jwt::derive_jti(username, session_nonce, iat_quantized);
    let claims = jwt::Claims {
        iss: &metadata.issuer,
        sub: username,
        aud: &metadata.audience,
        iat: iat_quantized,
        exp: iat_quantized + jwt::TOKEN_LIFETIME,
        jti: &jti,
        cnf_jkt,
    };
    jwt::signing_input(&jwt::header(&metadata.kid), &claims.to_json())
}

impl Server {
    pub fn new(id: ParticipantId, signing_key_share: Share, metadata: IdpMetadata) -> Self {
        Server {
            id,
            signing_key_share,
            metadata,
            users: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// 登録。クライアントから (TOPRF 鍵シェア, h_i) を受け取って保存するだけ。
    pub fn register(&mut self, username: &str, record: UserRecord) {
        self.users.insert(username.to_string(), record);
    }

    /// 侵害シミュレーション用。このサーバが掌握されたとき攻撃者が得る情報の全て。
    ///
    /// テストで「1 台掌握しても偽造できない」ことを実証するために公開している。
    pub fn breach(&self, username: &str) -> Option<(UserRecord, Share)> {
        self.users
            .get(username)
            .map(|record| (*record, self.signing_key_share))
    }

    /// Round 1（前処理可能）。ノンスを引いてコミットメントを公開する。
    pub fn preprocess(&mut self, session_nonce: [u8; 16]) -> Commitment {
        let (nonces, commitment) = tsign::commit(self.id);
        self.pending.insert(session_nonce, nonces);
        commitment
    }

    /// Round 2。**パスワードの検証は一切しない。**
    pub fn sign_on(&mut self, request: &SignOnRequest) -> Result<SignOnResponse, Error> {
        let record = *self.users.get(&request.username).ok_or(Error::UnknownUser)?;

        // クライアントが提案した iat が自分の時計と整合するか確認する。
        // 量子化するのはノード間の時計ズレを吸収するため（論点D）。
        let iat = jwt::quantize_time(request.iat);
        if request.iat.abs_diff(now()) > jwt::TIME_QUANTUM * 2 {
            return Err(Error::ClockSkew);
        }

        let nonces = self
            .pending
            .remove(&request.session_nonce)
            .ok_or(Error::NoPreprocessedNonce)?;

        // TOPRF の部分評価。パスワードの中身は分からないまま計算できる。
        let toprf_partial = toprf::evaluate(&record.toprf_key_share, &request.blinded);

        // ペイロードは **自分のレコードの username から** 構築する。
        // クライアントから渡されたものに署名することは決してない。
        let signing_input = build_signing_input(
            &self.metadata,
            &request.username,
            &request.cnf_jkt,
            &request.session_nonce,
            iat,
        );

        // 署名シェアを無条件に生成する。
        let share = tsign::sign_share(
            &self.signing_key_share,
            &nonces,
            signing_input.as_bytes(),
            &request.commitments,
            &self.metadata.public_key,
        );

        // h_i で暗号化する。ここが束縛。AAD に署名対象を入れて、
        // このシェアが別セッションに流用されるのを防ぐ。
        let cipher = ChaCha20Poly1305::new(&Key::from(record.server_key));
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(aead_nonce(&request.session_nonce, self.id)),
                Payload {
                    msg: share.as_bytes(),
                    aad: signing_input.as_bytes(),
                },
            )
            .expect("ChaCha20-Poly1305 の暗号化は失敗しない");

        Ok(SignOnResponse {
            id: self.id,
            toprf_partial,
            ciphertext,
        })
    }
}

/// 登録処理。クライアントが TOPRF 鍵を生成し、シェアと h_i を各サーバに配る。
///
/// PASTA の multi-client security 要件により、**TOPRF 鍵はクライアントごと**に作る。
pub fn register(
    servers: &mut [Server],
    username: &str,
    password: &[u8],
    threshold: ParticipantId,
) {
    let n = servers.len() as ParticipantId;
    let key_shares = toprf::generate_key(n, threshold);

    // クライアントは鍵を自分で作ったので、h をローカルで計算できる。
    let (blinding, blinded) = toprf::blind(password);
    let partials: Vec<_> = key_shares
        .iter()
        .take(threshold as usize)
        .map(|s| (s.id, toprf::evaluate(s, &blinded)))
        .collect();
    let h = toprf::finalize(password, &toprf::unblind(&blinding, &partials));

    for (server, key_share) in servers.iter_mut().zip(key_shares.iter()) {
        server.register(
            username,
            UserRecord {
                toprf_key_share: *key_share,
                // h ではなく h_i を渡す。h はどのサーバにも渡らない。
                server_key: toprf::derive_server_key(&h, server.id),
            },
        );
    }
}

/// クライアント側の sign-on 進行状態。
pub struct PendingSignOn {
    blinding: Blinding,
    username: String,
    cnf_jkt: String,
    session_nonce: [u8; 16],
    iat: u64,
    commitments: Vec<Commitment>,
}

/// Round 2 のリクエストを組み立てる。
pub fn begin_sign_on(
    username: &str,
    password: &[u8],
    cnf_jkt: &str,
    session_nonce: [u8; 16],
    commitments: Vec<Commitment>,
) -> (PendingSignOn, SignOnRequest) {
    let (blinding, blinded) = toprf::blind(password);
    let iat = now();

    let request = SignOnRequest {
        username: username.to_string(),
        blinded,
        cnf_jkt: cnf_jkt.to_string(),
        session_nonce,
        iat,
        commitments: commitments.clone(),
    };

    (
        PendingSignOn {
            blinding,
            username: username.to_string(),
            cnf_jkt: cnf_jkt.to_string(),
            session_nonce,
            iat,
            commitments,
        },
        request,
    )
}

/// レスポンスを結合してアクセストークンを得る。**検証はここで起きる。**
pub fn finish_sign_on(
    pending: &PendingSignOn,
    password: &[u8],
    metadata: &IdpMetadata,
    responses: &[SignOnResponse],
    threshold: ParticipantId,
) -> Result<String, Error> {
    if responses.len() < threshold as usize {
        return Err(Error::NotEnoughShares);
    }

    // 1. TOPRF の部分評価を結合して h を復元する。
    let partials: Vec<_> = responses
        .iter()
        .map(|r| (r.id, r.toprf_partial))
        .collect();
    let h = toprf::finalize(password, &toprf::unblind(&pending.blinding, &partials));

    // 2. サーバが署名した対象を、同じ手順で再構築する。
    let iat = jwt::quantize_time(pending.iat);
    let signing_input = build_signing_input(
        metadata,
        &pending.username,
        &pending.cnf_jkt,
        &pending.session_nonce,
        iat,
    );

    // 3. h_i を導出して復号する。パスワードが違えばここで全部失敗する。
    let mut shares = Vec::with_capacity(responses.len());
    for response in responses {
        let server_key = toprf::derive_server_key(&h, response.id);
        let cipher = ChaCha20Poly1305::new(&Key::from(server_key));

        let plaintext = cipher
            .decrypt(
                &Nonce::from(aead_nonce(&pending.session_nonce, response.id)),
                Payload {
                    msg: &response.ciphertext,
                    aad: signing_input.as_bytes(),
                },
            )
            .map_err(|_| Error::AuthenticationFailed)?;

        let bytes: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| Error::AuthenticationFailed)?;
        let share = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or(Error::AuthenticationFailed)?;
        shares.push(share);
    }

    // 4. 署名シェアを束ねる。壊れたトークンを掴まされていないか自分で検証してから返す。
    let signature = tsign::aggregate(signing_input.as_bytes(), &pending.commitments, &shares);
    if !tsign::verify(&metadata.public_key, signing_input.as_bytes(), &signature) {
        return Err(Error::InvalidSignature);
    }

    Ok(jwt::assemble(&signing_input, &signature))
}

/// RP 側の検証。署名対象は JWT の先頭 2 セグメント。
pub fn verify_token(metadata: &IdpMetadata, token: &str) -> bool {
    let Some(last_dot) = token.rfind('.') else {
        return false;
    };
    let (signing_input, encoded_signature) = token.split_at(last_dot);

    let Some(signature) = jwt::decode_base64url(&encoded_signature[1..]) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature.as_slice()) else {
        return false;
    };

    tsign::verify(&metadata.public_key, signing_input.as_bytes(), &signature)
}
