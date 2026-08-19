use crate::field::Field;
use crate::oblivious_transfer as ot;

pub fn send(stream: &std::net::TcpStream, a: &Field) -> Field {
    let mut r_list = Vec::new();
    // P = 2^61 - 1
    for _ in 0..61 {
        r_list.push(Field::random());
    }

    for (i, r) in r_list.iter().enumerate() {
        let m0 = r;
        let m1 = &Field::add(m0, &Field::mul(a, &Field::from(1u64 << i)));
        ot::send(stream, m0, m1);
    }

    let r_sum = r_list
        .iter()
        .fold(Field::from(0), |acc, r| Field::add(&acc, r));
    Field::sub(&Field::from(0), &r_sum)
}

pub fn recv(stream: &std::net::TcpStream, b: &Field) -> Field {
    let mut v = Field::from(0);
    for i in 0..61 {
        let m = ot::recv(stream, b.bit_of(i));
        v = Field::add(&v, &m);
    }

    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn run(a: Field, b: Field) -> (Field, Field) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let sender = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            send(&stream, &a)
        });

        let receiver_stream = TcpStream::connect(addr).unwrap();
        let v = recv(&receiver_stream, &b);

        let u = sender.join().unwrap();

        (u, v)
    }

    #[test]
    fn randoms() {
        for _ in 0..10 {
            let a = Field::random();
            let b = Field::random();
            let (u, v) = run(a, b);
            assert_eq!(
                u64::from(&Field::add(&u, &v)),
                u64::from(&Field::mul(&a, &b))
            );
        }
    }

    #[test]
    fn top_bit_of_b_is_set() {
        let a = Field::from(2);
        let b = Field::from(1 << 60);
        let (u, v) = run(a, b);
        assert_eq!(
            u64::from(&Field::add(&u, &v)),
            u64::from(&Field::mul(&a, &b))
        );
    }

    #[test]
    fn zero() {
        let a = Field::from(0);
        let b = Field::from(0);
        let (u, v) = run(a, b);
        assert_eq!(
            u64::from(&Field::add(&u, &v)),
            u64::from(&Field::mul(&a, &b))
        );
    }
}
