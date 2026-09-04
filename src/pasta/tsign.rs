//! FROST 方式の閾値 Schnorr 署名（Ed25519）。
//!
//! 出力は **標準の Ed25519 署名** なので、RP は閾値署名であることを知らないまま
//! 通常の JWT ライブラリ（`alg: EdDSA`, RFC 8037）で検証できる。これが互換性の勝ち筋。
//!
//! 署名シェア z_i = d_i + ρ_i·e_i + λ_i·s_i·c は **全てローカル計算の線形演算**で、
//! 参加者間の乗算プロトコルを必要としない。つまり Beaver triple は要らない。
//!
//! ⚠️ 教育用の自前実装。RFC 9591 とバイト列レベルで相互運用する意図はない
//!    （検証側の互換性は Ed25519 の検証式に依存しており、そちらは満たしている）。

use curve25519_dalek::{EdwardsPoint, Scalar, edwards::CompressedEdwardsY, traits::Identity};
use sha2::{Digest, Sha512};

use super::shamir::{ParticipantId, Share, lagrange_coeff, random_scalar};

/// グループ公開鍵 A = [s]·B。JWKS で公開する値。
#[derive(Clone, Copy, Debug)]
pub struct GroupPublicKey(pub EdwardsPoint);

impl GroupPublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

/// 署名鍵を (t, n) で分散して生成する。マスター鍵はどこにも保持されない。
pub fn generate_key(n: ParticipantId, t: ParticipantId) -> (Vec<Share>, GroupPublicKey) {
    let secret = random_scalar();
    let public = GroupPublicKey(EdwardsPoint::mul_base(&secret));
    (super::shamir::split(&secret, n, t), public)
}

/// Round 1 の秘密ノンス。1 回の署名で使い捨てる。
pub struct Nonces {
    d: Scalar,
    e: Scalar,
}

/// Round 1 のコミットメント。事前配布（前処理）できる。
#[derive(Clone, Copy, Debug)]
pub struct Commitment {
    pub id: ParticipantId,
    pub big_d: EdwardsPoint,
    pub big_e: EdwardsPoint,
}

/// Round 1: ノンスを引いてコミットメントを作る。メッセージには依存しない。
pub fn commit(id: ParticipantId) -> (Nonces, Commitment) {
    let d = random_scalar();
    let e = random_scalar();
    (
        Nonces { d, e },
        Commitment {
            id,
            big_d: EdwardsPoint::mul_base(&d),
            big_e: EdwardsPoint::mul_base(&e),
        },
    )
}

/// コミットメント一覧を決定的にエンコードする。全参加者が同じバイト列を得る必要がある。
fn encode_commitments(commitments: &[Commitment]) -> Vec<u8> {
    let mut sorted = commitments.to_vec();
    sorted.sort_by_key(|c| c.id);

    let mut out = Vec::with_capacity(sorted.len() * 66);
    for c in &sorted {
        out.extend_from_slice(&c.id.to_le_bytes());
        out.extend_from_slice(c.big_d.compress().as_bytes());
        out.extend_from_slice(c.big_e.compress().as_bytes());
    }
    out
}

/// 束縛係数 ρ_i。コミットメントの入れ替え攻撃を防ぐ。
fn binding_factor(id: ParticipantId, message: &[u8], encoded: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"PASTA-FROST-RHO");
    hasher.update(id.to_le_bytes());
    hasher.update((message.len() as u64).to_le_bytes());
    hasher.update(message);
    hasher.update(encoded);
    Scalar::from_hash(hasher)
}

/// グループコミットメント R = Σ_j (D_j + [ρ_j]·E_j)
fn group_commitment(message: &[u8], commitments: &[Commitment]) -> EdwardsPoint {
    let encoded = encode_commitments(commitments);
    commitments
        .iter()
        .map(|c| c.big_d + c.big_e * binding_factor(c.id, message, &encoded))
        .fold(EdwardsPoint::identity(), |acc, p| acc + p)
}

/// Ed25519 のチャレンジ c = SHA512(R ‖ A ‖ M) mod ℓ。
///
/// **ここが標準 Ed25519 と一致していることが互換性の要**。
fn challenge(r: &EdwardsPoint, public: &GroupPublicKey, message: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r.compress().as_bytes());
    hasher.update(public.0.compress().as_bytes());
    hasher.update(message);
    Scalar::from_hash(hasher)
}

/// Round 2: 署名シェア z_i = d_i + ρ_i·e_i + λ_i·s_i·c を計算する。
///
/// 通信は不要で、全てローカルの加算・乗算だけで済む。
pub fn sign_share(
    key_share: &Share,
    nonces: &Nonces,
    message: &[u8],
    commitments: &[Commitment],
    public: &GroupPublicKey,
) -> Scalar {
    let encoded = encode_commitments(commitments);
    let rho = binding_factor(key_share.id, message, &encoded);
    let r = group_commitment(message, commitments);
    let c = challenge(&r, public, message);

    let ids: Vec<ParticipantId> = commitments.iter().map(|c| c.id).collect();
    let lambda = lagrange_coeff(&ids, key_share.id);

    nonces.d + rho * nonces.e + lambda * key_share.value * c
}

/// 署名シェアを束ねて 64 バイトの Ed25519 署名にする。
pub fn aggregate(
    message: &[u8],
    commitments: &[Commitment],
    shares: &[Scalar],
) -> [u8; 64] {
    let r = group_commitment(message, commitments);
    let z = shares.iter().fold(Scalar::ZERO, |acc, s| acc + s);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r.compress().as_bytes());
    sig[32..].copy_from_slice(z.as_bytes());
    sig
}

/// 標準 Ed25519 の検証式 [z]·B == R + [c]·A。
///
/// RP 側は普通の Ed25519 検証器を使うので、ここは「同じ式で通ること」の確認用。
pub fn verify(public: &GroupPublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
    let Some(r) = CompressedEdwardsY::from_slice(&signature[..32])
        .ok()
        .and_then(|c| c.decompress())
    else {
        return false;
    };

    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&signature[32..]);
    let Some(z) = Option::<Scalar>::from(Scalar::from_canonical_bytes(z_bytes)) else {
        return false;
    };

    let c = challenge(&r, public, message);
    EdwardsPoint::mul_base(&z) == r + public.0 * c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_signing(n: ParticipantId, t: ParticipantId, signers: &[usize]) -> ([u8; 64], GroupPublicKey, Vec<u8>) {
        let (key_shares, public) = generate_key(n, t);
        let message = b"threshold signed message".to_vec();

        let prepared: Vec<(Nonces, Commitment)> =
            signers.iter().map(|&i| commit(key_shares[i].id)).collect();
        let commitments: Vec<Commitment> = prepared.iter().map(|(_, c)| *c).collect();

        let shares: Vec<Scalar> = signers
            .iter()
            .zip(prepared.iter())
            .map(|(&i, (nonces, _))| {
                sign_share(&key_shares[i], nonces, &message, &commitments, &public)
            })
            .collect();

        (aggregate(&message, &commitments, &shares), public, message)
    }

    #[test]
    fn threshold_signature_verifies() {
        let (sig, public, message) = run_signing(5, 3, &[0, 1, 2]);
        assert!(verify(&public, &message, &sig));
    }

    /// どの t 台の組み合わせでも、同じグループ公開鍵で検証できる署名になる。
    #[test]
    fn any_quorum_produces_valid_signature() {
        let (sig, public, message) = run_signing(5, 3, &[1, 3, 4]);
        assert!(verify(&public, &message, &sig));
    }

    /// t 未満では有効な署名にならない。
    #[test]
    fn below_threshold_produces_invalid_signature() {
        let (sig, public, message) = run_signing(5, 3, &[0, 1]);
        assert!(!verify(&public, &message, &sig));
    }

    /// メッセージを差し替えると当然落ちる。
    #[test]
    fn tampered_message_rejected() {
        let (sig, public, _) = run_signing(3, 3, &[0, 1, 2]);
        assert!(!verify(&public, b"different message", &sig));
    }
}
