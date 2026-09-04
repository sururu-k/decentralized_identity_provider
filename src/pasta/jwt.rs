//! 決定的な JWT 構築。
//!
//! t 台のノードが **バイト単位で同一の** 署名対象を作らないと閾値署名は成立しない。
//! そのため以下を全て決定的にする:
//!
//! - `iat` / `exp` — 各ノードのローカル時刻ではズレるので、量子化した値を使う
//! - `jti` — 乱数ではなくセッション nonce から導出する
//! - JSON — キー順を固定し、空白を入れない（外部シリアライザに任せない）

use sha2::{Digest, Sha512};

/// `iat` を丸める粒度（秒）。ノード間の時計ズレをこの範囲で吸収する。
pub const TIME_QUANTUM: u64 = 30;

/// アクセストークンの寿命（秒）。
pub const TOKEN_LIFETIME: u64 = 300;

pub fn quantize_time(unix_seconds: u64) -> u64 {
    unix_seconds - (unix_seconds % TIME_QUANTUM)
}

fn base64url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;

        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// セッション nonce から `jti` を導出する。全ノードが同じ値に到達する。
pub fn derive_jti(username: &str, nonce: &[u8; 16], iat: u64) -> String {
    let mut hasher = Sha512::new();
    hasher.update(b"PASTA-JTI");
    hasher.update(username.as_bytes());
    hasher.update(nonce);
    hasher.update(iat.to_le_bytes());
    hex(&hasher.finalize()[..16])
}

/// JWT のクレーム。**フィールド順は固定**で、シリアライズ結果は完全に決定的。
pub struct Claims<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub iat: u64,
    pub exp: u64,
    pub jti: &'a str,
    /// DPoP の確認鍵 thumbprint (RFC 9449 の `cnf.jkt`)。
    /// これでトークンの持ち主が認証を通した者に束縛される。
    pub cnf_jkt: &'a str,
}

/// JSON 文字列値のエスケープ。PoC なので制御文字は弾く。
fn escape(value: &str) -> String {
    assert!(
        !value.chars().any(|c| c.is_control()),
        "クレームに制御文字は入れられない"
    );
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

impl Claims<'_> {
    /// キー順を固定した JSON。空白なし。全ノードで同一バイト列になる。
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"iss":"{}","sub":"{}","aud":"{}","iat":{},"exp":{},"jti":"{}","cnf":{{"jkt":"{}"}}}}"#,
            escape(self.iss),
            escape(self.sub),
            escape(self.aud),
            self.iat,
            self.exp,
            escape(self.jti),
            escape(self.cnf_jkt),
        )
    }
}

/// JWT ヘッダ。`alg: EdDSA` は RFC 8037 で標準化されている。
pub fn header(kid: &str) -> String {
    format!(r#"{{"alg":"EdDSA","typ":"JWT","kid":"{}"}}"#, escape(kid))
}

/// 署名対象 = base64url(header) ‖ "." ‖ base64url(payload)
pub fn signing_input(header: &str, payload: &str) -> String {
    format!("{}.{}", base64url(header.as_bytes()), base64url(payload.as_bytes()))
}

/// base64url をデコードする（パディング無し）。
pub fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    let value_of = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    };

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.as_bytes().chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= value_of(c)? << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

/// 完成した JWT を組み立てる。
pub fn assemble(signing_input: &str, signature: &[u8; 64]) -> String {
    format!("{}.{}", signing_input, base64url(signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_roundtrips() {
        for case in [b"".as_slice(), b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(decode_base64url(&base64url(case)).unwrap(), case);
        }
        let wide: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode_base64url(&base64url(&wide)).unwrap(), wide);
    }

    /// URL-safe 文字だけが出る（`+` `/` `=` が現れない）。
    #[test]
    fn base64url_is_url_safe() {
        let encoded = base64url(&[0xfb, 0xff, 0xfe, 0xff]);
        assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
    }

    #[test]
    fn claims_serialization_is_deterministic() {
        let claims = Claims {
            iss: "https://idp.example",
            sub: "alice",
            aud: "https://rp.example",
            iat: 1_700_000_010,
            exp: 1_700_000_310,
            jti: "abc123",
            cnf_jkt: "thumbprint",
        };
        assert_eq!(claims.to_json(), claims.to_json());
        assert_eq!(
            claims.to_json(),
            r#"{"iss":"https://idp.example","sub":"alice","aud":"https://rp.example","iat":1700000010,"exp":1700000310,"jti":"abc123","cnf":{"jkt":"thumbprint"}}"#
        );
    }

    /// ⚠️ 量子化だけでは時計ズレを吸収できない。境界をまたぐと値がズレる。
    ///
    /// 決定性は量子化ではなく「**トランスクリプト中の 1 つの値を全ノードが使う**」ことで
    /// 担保する必要がある。本 PoC ではクライアントが提案した `iat` を全サーバが使い、
    /// 各サーバは自分の時計では**許容範囲の検査にだけ**使う。
    #[test]
    fn quantization_alone_does_not_absorb_skew() {
        // 同じバケットに入れば一致する
        assert_eq!(quantize_time(1_700_000_000), quantize_time(1_700_000_005));

        // わずか 29 秒差でも、境界をまたげばズレる ← ここが落とし穴
        assert_ne!(quantize_time(1_700_000_000), quantize_time(1_700_000_029));

        // 量子化後の値は必ず TIME_QUANTUM の倍数になる
        assert_eq!(quantize_time(1_700_000_029) % TIME_QUANTUM, 0);
    }
}
