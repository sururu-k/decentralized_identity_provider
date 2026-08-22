//! Ed25519 のスカラー体上の Shamir 秘密分散。
//!
//! 既存の `crate::field` は GF(2^61-1) 上で動いているが、閾値署名と TOPRF は
//! 曲線のスカラー体 (ℓ ≈ 2^252) 上でなければならないので、こちらを別に用意する。

use curve25519_dalek::Scalar;
use rand::prelude::*;

pub type ParticipantId = u16;

#[derive(Clone, Copy, Debug)]
pub struct Share {
    pub id: ParticipantId,
    pub value: Scalar,
}

/// OS 乱数 64 バイトを法 ℓ に落として一様なスカラーを得る。
pub fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// `secret` を (t, n) 閾値で分散する。x 座標は 1..=n。
pub fn split(secret: &Scalar, n: ParticipantId, t: ParticipantId) -> Vec<Share> {
    assert!(t >= 1 && t <= n, "1 <= t <= n が必要");

    // f(x) = secret + c_1 x + ... + c_{t-1} x^{t-1}
    let coeffs: Vec<Scalar> = (1..t).map(|_| random_scalar()).collect();

    (1..=n)
        .map(|id| {
            let x = Scalar::from(id as u64);
            // Horner 法で f(x) を評価する
            let mut acc = Scalar::ZERO;
            for c in coeffs.iter().rev() {
                acc = acc * x + c;
            }
            Share {
                id,
                value: acc * x + secret,
            }
        })
        .collect()
}

/// 参加者集合 `ids` における `target` のラグランジュ係数 λ_i = Π_{j≠i} x_j / (x_j - x_i)。
pub fn lagrange_coeff(ids: &[ParticipantId], target: ParticipantId) -> Scalar {
    let xi = Scalar::from(target as u64);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    for &j in ids {
        if j == target {
            continue;
        }
        let xj = Scalar::from(j as u64);
        num *= xj;
        den *= xj - xi;
    }

    num * den.invert()
}

/// t 個以上のシェアから秘密を復元する。テストと、鍵が「揃っていない」ことの確認用。
pub fn reconstruct(shares: &[Share]) -> Scalar {
    let ids: Vec<ParticipantId> = shares.iter().map(|s| s.id).collect();
    shares
        .iter()
        .map(|s| lagrange_coeff(&ids, s.id) * s.value)
        .fold(Scalar::ZERO, |acc, v| acc + v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_of_n_reconstructs() {
        let secret = random_scalar();
        let shares = split(&secret, 5, 3);

        // 任意の 3 枚で復元できる
        assert_eq!(reconstruct(&shares[0..3]), secret);
        assert_eq!(reconstruct(&[shares[0], shares[2], shares[4]]), secret);
    }

    #[test]
    fn fewer_than_t_reveals_nothing() {
        let secret = random_scalar();
        let shares = split(&secret, 5, 3);

        // 2 枚だけでは復元できない（ラグランジュ補間の次数が足りない）
        assert_ne!(reconstruct(&shares[0..2]), secret);
    }
}
