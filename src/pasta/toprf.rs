//! 2HashTDH — Jarecki et al. [JKKX17] の閾値 OPRF。PASTA が使っているもの。
//!
//! サーバ側の秘密 k を n 台に分散し、クライアントはパスワードを一切明かさずに
//! `h = F_k(password)` を得る。t 台の協力が無ければ誰も F_k を計算できないので、
//! 1 台侵害されただけではオフライン辞書攻撃が成立しない。
//!
//! PASTA の要求どおり **TOPRF 鍵はクライアントごとに生成する**。
//! 全クライアントで鍵を共有すると、1 人分の総当たりで集めた PRF 値を
//! 他のクライアントへのオフライン攻撃に流用されてしまう。

use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

use super::shamir::{ParticipantId, Share, lagrange_coeff, random_scalar};

/// H2: X → G。パスワードを群の元へ写す。
fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"PASTA-TOPRF-H2");
    hasher.update((input.len() as u64).to_le_bytes());
    hasher.update(input);
    let digest = hasher.finalize();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// クライアント側の目隠し状態。`r` は復元時まで秘匿する。
pub struct Blinding {
    r: Scalar,
}

/// パスワードを目隠しして送信用の点を作る。a = [r]·H2(pw)
pub fn blind(password: &[u8]) -> (Blinding, RistrettoPoint) {
    let r = random_scalar();
    (Blinding { r }, hash_to_group(password) * r)
}

/// サーバ i の部分評価。b_i = [k_i]·a
///
/// サーバは `a` から password を復元できない（離散対数と目隠しのため）。
pub fn evaluate(key_share: &Share, blinded: &RistrettoPoint) -> RistrettoPoint {
    blinded * key_share.value
}

/// 部分評価をラグランジュ補間で結合し、目隠しを外す。z = H2(pw)^k
pub fn unblind(
    blinding: &Blinding,
    partials: &[(ParticipantId, RistrettoPoint)],
) -> RistrettoPoint {
    let ids: Vec<ParticipantId> = partials.iter().map(|(id, _)| *id).collect();

    let combined = partials
        .iter()
        .map(|(id, point)| point * lagrange_coeff(&ids, *id))
        .fold(RistrettoPoint::default(), |acc, p| acc + p);

    combined * blinding.r.invert()
}

/// H1: X × G → {0,1}^256。最終的な PRF 出力 h を得る。
pub fn finalize(password: &[u8], z: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"PASTA-TOPRF-H1");
    hasher.update((password.len() as u64).to_le_bytes());
    hasher.update(password);
    hasher.update(z.compress().as_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// サーバ i に渡す派生値 h_i = H'(h, i)。
///
/// PASTA の client impersonation 対策。h そのものはどのサーバにも渡らないので、
/// 1 台侵害しても攻撃者が得るのはその台の h_i だけで、残りは秘密のまま。
pub fn derive_server_key(h: &[u8; 32], id: ParticipantId) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"PASTA-TOPRF-H-PRIME");
    hasher.update(h);
    hasher.update(id.to_le_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// クライアント固有の TOPRF 鍵を作り、(t, n) で分散する。登録時に一度だけ実行。
pub fn generate_key(n: ParticipantId, t: ParticipantId) -> Vec<Share> {
    super::shamir::split(&random_scalar(), n, t)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// どの t 台の組み合わせでも同じ h が得られる（＝決定的な PRF である）。
    #[test]
    fn any_quorum_yields_same_output() {
        let key_shares = generate_key(5, 3);
        let password = b"correct horse battery staple";

        let evaluate_with = |subset: &[usize]| {
            let (blinding, blinded) = blind(password);
            let partials: Vec<_> = subset
                .iter()
                .map(|&i| (key_shares[i].id, evaluate(&key_shares[i], &blinded)))
                .collect();
            finalize(password, &unblind(&blinding, &partials))
        };

        assert_eq!(evaluate_with(&[0, 1, 2]), evaluate_with(&[2, 3, 4]));
    }

    /// パスワードが違えば出力も違う。
    #[test]
    fn different_password_yields_different_output() {
        let key_shares = generate_key(3, 3);

        let run = |password: &[u8]| {
            let (blinding, blinded) = blind(password);
            let partials: Vec<_> = key_shares
                .iter()
                .map(|s| (s.id, evaluate(s, &blinded)))
                .collect();
            finalize(password, &unblind(&blinding, &partials))
        };

        assert_ne!(run(b"hunter2"), run(b"hunter3"));
    }

    /// t 未満では正しい h に到達できない。
    #[test]
    fn below_threshold_fails() {
        let key_shares = generate_key(5, 3);
        let password = b"hunter2";

        let (blinding, blinded) = blind(password);
        let full: Vec<_> = key_shares[0..3]
            .iter()
            .map(|s| (s.id, evaluate(s, &blinded)))
            .collect();
        let short: Vec<_> = key_shares[0..2]
            .iter()
            .map(|s| (s.id, evaluate(s, &blinded)))
            .collect();

        assert_ne!(
            finalize(password, &unblind(&blinding, &full)),
            finalize(password, &unblind(&blinding, &short))
        );
    }
}
