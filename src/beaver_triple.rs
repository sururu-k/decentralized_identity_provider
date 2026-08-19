use crate::field::Field;
use crate::gilboa;
use crate::node_connection::NodeNetwork;

pub struct BeaverTripleShare {
    a_share: Field,
    b_share: Field,
    c_share: Field,
}

pub fn beaver_triple(net: &NodeNetwork) -> BeaverTripleShare {
    let a_share = Field::random();
    let b_share = Field::random();

    let c_share = std::thread::scope(|scope| {
        let sum = [
            scope.spawn(|| gilboa::send(net.stream_left_write(), &a_share)),
            scope.spawn(|| gilboa::send(net.stream_right_write(), &a_share)),
            scope.spawn(|| gilboa::recv(net.stream_left_read(), &b_share)),
            scope.spawn(|| gilboa::recv(net.stream_right_read(), &b_share)),
        ]
        .into_iter()
        .map(|th| th.join().unwrap())
        .fold(Field::from(0), |acc, s| Field::add(&acc, &s));

        Field::add(&sum, &Field::mul(&a_share, &b_share))
    });

    BeaverTripleShare {
        a_share,
        b_share,
        c_share,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_connection::NODE_NUM;

    #[test]
    fn random() {
        let nodes: Vec<_> = (0..NODE_NUM)
            .map(|id| {
                std::thread::spawn(move || {
                    let net = NodeNetwork::new(id);
                    beaver_triple(&net)
                })
            })
            .collect();

        let bt_share: Vec<BeaverTripleShare> =
            nodes.into_iter().map(|n| n.join().unwrap()).collect();

        let sum = |f: fn(&BeaverTripleShare) -> &Field| {
            bt_share
                .iter()
                .fold(Field::from(0), |acc, s| Field::add(&acc, f(s)))
        };

        let a = sum(|s| &s.a_share);
        let b = sum(|s| &s.b_share);
        let c = sum(|s| &s.c_share);

        assert_eq!(u64::from(&Field::mul(&a, &b)), u64::from(&c));
    }
}
