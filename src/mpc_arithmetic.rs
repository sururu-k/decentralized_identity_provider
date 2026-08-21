use crate::beaver_triple::{BeaverTripleShare, beaver_triple};
use crate::field::Field;
use crate::node_connection::{NodeId, NodeNetwork};
use rand::prelude::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

type ShareBucketId = u128;
type ShareId = u128;

pub struct MpcArithmetic {
    net: NodeNetwork,
    shares: HashMap<ShareId, Field>,
    bt_shares: Vec<BeaverTripleShare>,
}

impl MpcArithmetic {
    fn new(node_id: NodeId) -> Self {
        let net = NodeNetwork::new(node_id);

        let mut bt_shares = Vec::new();
        for _ in 0..10 {
            let bt = beaver_triple(&net);
            bt_shares.push(bt);
        }

        MpcArithmetic {
            net,
            shares: HashMap::new(),
            bt_shares,
        }
    }

    fn set_share(&mut self, share: Field) -> u128 {
        let mut r = rand::rng();
        let share_id = r.random_range(0..ShareId::MAX);

        self.shares.insert(share_id, share);

        share_id
    }

    fn add(&mut self, share_id_a: ShareId, share_id_b: ShareId) -> ShareId {
        let a = *self.shares.get(&share_id_a).expect("No share for given id");
        let b = *self.shares.get(&share_id_b).expect("No share for given id");
        let c = Field::add(&a, &b);
        self.set_share(c)
    }

    fn mul(&mut self, share_id_a: ShareId, share_id_b: ShareId) -> ShareId {
        let a_share = *self.shares.get(&share_id_a).expect("No share for given id");
        let b_share = *self.shares.get(&share_id_b).expect("No share for given id");
        let bt = self.bt_shares.pop().expect("No beaver triples");

        let d_share = Field::sub(&a_share, &bt.a_share);
        let d_share_id = self.set_share(d_share);
        let e_share = Field::sub(&b_share, &bt.b_share);
        let e_share_id = self.set_share(e_share);

        let d = self.open(d_share_id);
        let e = self.open(e_share_id);

        let z_share_1 = Field::add(
            &Field::add(&bt.c_share, &Field::mul(&d, &bt.b_share)),
            &Field::mul(&e, &bt.a_share),
        );
        let z_share = match self.net.self_id {
            0 => Field::add(&z_share_1, &Field::mul(&d, &e)),
            _ => z_share_1,
        };

        self.set_share(z_share)
    }

    fn open(&mut self, share_id: ShareId) -> Field {
        let share = *self.shares.get(&share_id).expect("No share for given id");

        let write = |mut stream: &TcpStream| {
            let bytes = <[u8; 8]>::from(&share);
            stream.write_all(&bytes).expect("Can't write share value");
        };

        let read = |mut stream: &TcpStream| {
            let mut buf = [0u8; 8];
            stream.read_exact(&mut buf).expect("Can't read share value");
            Field::from(buf)
        };

        std::thread::scope(|scope| {
            let th_write = [
                scope.spawn(|| write(self.net.stream_left_write())),
                scope.spawn(|| write(self.net.stream_right_write())),
            ];
            let th_read = [
                scope.spawn(|| read(self.net.stream_left_read())),
                scope.spawn(|| read(self.net.stream_right_read())),
            ];

            let _ = th_write.into_iter().map(|th| th.join().unwrap());

            th_read
                .into_iter()
                .map(|th| th.join().unwrap())
                .fold(share, |acc, s| Field::add(&acc, &s))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{field::P, node_connection::NODE_NUM};

    fn to_field(v: Vec<u64>) -> Vec<Field> {
        v.into_iter().map(Field::from).collect()
    }

    fn add(
        mpc_participants: &mut [MpcArithmetic],
        share_values_a: Vec<u64>,
        share_values_b: Vec<u64>,
    ) -> Vec<u128> {
        let share_ids_a: Vec<ShareId> = mpc_participants
            .iter_mut()
            .zip(to_field(share_values_a))
            .map(|(p, s)| p.set_share(s))
            .collect();
        let share_ids_b: Vec<ShareId> = mpc_participants
            .iter_mut()
            .zip(to_field(share_values_b))
            .map(|(p, s)| p.set_share(s))
            .collect();
        let share_ids = share_ids_a.into_iter().zip(share_ids_b);

        std::thread::scope(|scope| {
            mpc_participants
                .iter_mut()
                .zip(share_ids)
                .map(|(p, (a, b))| scope.spawn(move || p.add(a, b)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|th| th.join().unwrap())
                .collect()
        })
    }

    fn mul(
        mpc_participants: &mut [MpcArithmetic],
        share_values_a: Vec<u64>,
        share_values_b: Vec<u64>,
    ) -> Vec<u128> {
        let share_ids_a: Vec<ShareId> = mpc_participants
            .iter_mut()
            .zip(to_field(share_values_a))
            .map(|(p, s)| p.set_share(s))
            .collect();
        let share_ids_b: Vec<ShareId> = mpc_participants
            .iter_mut()
            .zip(to_field(share_values_b))
            .map(|(p, s)| p.set_share(s))
            .collect();
        let share_ids = share_ids_a.into_iter().zip(share_ids_b);

        std::thread::scope(|scope| {
            mpc_participants
                .iter_mut()
                .zip(share_ids)
                .map(|(p, (a, b))| scope.spawn(move || p.mul(a, b)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|th| th.join().unwrap())
                .collect()
        })
    }

    fn open(mpc_participants: &mut [MpcArithmetic], share_values: Vec<u64>) -> Vec<Field> {
        let share_ids: Vec<ShareId> = mpc_participants
            .iter_mut()
            .zip(to_field(share_values))
            .map(|(p, s)| p.set_share(s))
            .collect();

        std::thread::scope(|scope| {
            mpc_participants
                .iter_mut()
                .zip(share_ids)
                .map(|(p, sid)| scope.spawn(move || p.open(sid)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|th| th.join().unwrap())
                .collect()
        })
    }

    #[test]
    fn add_simple() {
        let mut mpc_participants: Vec<_> = std::thread::scope(|scope| {
            (0..NODE_NUM)
                .map(|id| scope.spawn(move || MpcArithmetic::new(id)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|th| th.join().unwrap())
                .collect()
        });

        let result = add(&mut mpc_participants, vec![1, 2, 3], vec![4, 5, 6]);
        let _ = mpc_participants
            .iter()
            .zip(result)
            .zip(vec![5, 7, 9])
            .map(|((p, share_id), answer)| {
                assert_eq!(u64::from(p.shares.get(&share_id).unwrap()), answer)
            })
            .collect::<Vec<_>>();
    }

    #[test]
    fn mul_simple() {
        let mut mpc_participants: Vec<_> = std::thread::scope(|scope| {
            (0..NODE_NUM)
                .map(|id| scope.spawn(move || MpcArithmetic::new(id)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|th| th.join().unwrap())
                .collect()
        });

        let mut collect = |share_values_a: Vec<u64>, share_values_b: Vec<u64>| {
            let result = mul(&mut mpc_participants, share_values_a, share_values_b);
            mpc_participants
                .iter()
                .zip(result)
                .map(|(p, share_id)| p.shares.get(&share_id).unwrap())
                .fold(Field::from(0), |acc, s| Field::add(&acc, s))
        };

        assert_eq!(u64::from(&collect(vec![1, 0, 0], vec![0, 0, 2])), 2);
        assert_eq!(u64::from(&collect(vec![1, 2, 3], vec![4, 5, 6])), 90);
        assert_eq!(u64::from(&collect(vec![P - 2, 1, 0], vec![0, 1, 1])), P - 2);
        assert_eq!(u64::from(&collect(vec![P - 3, 1, 3], vec![1, 1, P - 1])), 1);
    }

    #[test]
    fn open_simple() {
        let mut mpc_participants: Vec<_> = std::thread::scope(|scope| {
            (0..NODE_NUM)
                .map(|id| scope.spawn(move || MpcArithmetic::new(id)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|th| th.join().unwrap())
                .collect()
        });

        let _ = open(&mut mpc_participants, vec![1, 2, 3])
            .iter()
            .map(|v| assert_eq!(u64::from(v), 6u64))
            .collect::<Vec<_>>();
        let _ = open(&mut mpc_participants, vec![P - 1, 1, 2])
            .iter()
            .map(|v| assert_eq!(u64::from(v), 2u64))
            .collect::<Vec<_>>();
    }
}
