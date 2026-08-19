use crate::field::Field;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub fn send(mut stream: &std::net::TcpStream, org_m0: &Field, org_m1: &Field) {
    let m0 = u64::to_le_bytes(u64::from(org_m0));
    let m1 = u64::to_le_bytes(u64::from(org_m1));

    let y = curve25519_dalek::Scalar::random(&mut rand::rng());
    let s = y * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    stream
        .write_all(&s.compress().to_bytes())
        .expect("Can't send S value"); // [u8; 32]

    let mut buf = [0u8; 32];
    stream.read_exact(&mut buf).expect("Can't read R");
    let r = curve25519_dalek::ristretto::CompressedRistretto(buf)
        .decompress()
        .expect("Invalide R value");

    let t = y * s;
    let mut hasher0 = Sha256::new();
    hasher0.update([0]);
    hasher0.update((y * r).compress().to_bytes());
    let k0: [u8; 32] = hasher0.finalize().into();
    let masked_k0 = u64::from_le_bytes(k0[0..8].try_into().expect("Hash can't be masked"));
    let mut hasher1 = Sha256::new();
    hasher1.update([1]);
    hasher1.update((y * r - t).compress().to_bytes());
    let k1: [u8; 32] = hasher1.finalize().into();
    let masked_k1 = u64::from_le_bytes(k1[0..8].try_into().expect("Hash can't be masked"));

    let e0 = u64::from_le_bytes(m0) ^ masked_k0;
    let e1 = u64::from_le_bytes(m1) ^ masked_k1;
    stream.write_all(&e0.to_le_bytes()).expect("Can't send e0");
    stream.write_all(&e1.to_le_bytes()).expect("Can't send e1");
}

pub fn recv(mut stream: &std::net::TcpStream, c: bool) -> Field {
    let mut buf = [0u8; 32];
    stream.read_exact(&mut buf).expect("Can't receive S value");
    let s = curve25519_dalek::ristretto::CompressedRistretto(buf)
        .decompress()
        .expect("Invalid S value");

    let x = curve25519_dalek::Scalar::random(&mut rand::rng());
    let r0 = x * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let r1 = s + r0;
    let r = match c {
        true => r1,
        false => r0,
    };
    stream
        .write_all(&r.compress().to_bytes())
        .expect("Can't send R value");

    let mut e0 = [0u8; 8];
    stream.read_exact(&mut e0).expect("Can't receive e0");
    let mut e1 = [0u8; 8];
    stream.read_exact(&mut e1).expect("Can't receive e1");
    let ec = match c {
        true => e1,
        false => e0,
    };

    let mut hasher = Sha256::new();
    hasher.update([if c { 1 } else { 0 }]);
    hasher.update((x * s).compress().to_bytes());
    let kc: [u8; 32] = hasher.finalize().into();
    let masked_kc = u64::from_le_bytes(kc[0..8].try_into().expect("Hash can't be masked"));
    let m_c = u64::from_le_bytes(ec) ^ masked_kc;

    Field::from(m_c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn run_ot(choice: bool, m0: Field, m1: Field) -> Field {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let sender = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            send(&stream, &m0, &m1);
        });

        let receiver_stream = TcpStream::connect(addr).unwrap();
        let result = recv(&receiver_stream, choice);
        sender.join().unwrap();
        result
    }

    #[test]
    fn receives_m0_when_choice_is_false() {
        let m0 = Field::from(123);
        let m1 = Field::from(456);
        let result = run_ot(false, m0, m1);
        assert_eq!(u64::from(&result), u64::from(&m0));
    }

    #[test]
    fn receives_m1_when_choice_is_true() {
        let m0 = Field::from(123);
        let m1 = Field::from(456);
        let result = run_ot(true, m0, m1);
        assert_eq!(u64::from(&result), u64::from(&m1));
    }
}
