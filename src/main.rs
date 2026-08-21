mod beaver_triple;
mod field;
mod gilboa;
mod mpc_arithmetic;
mod node_connection;
mod oblivious_transfer;

use node_connection::{NodeId, NodeNetwork};

use crate::beaver_triple::beaver_triple;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let node_id: NodeId = args
        .get(1)
        .expect("Illegal options")
        .parse()
        .expect("node_id is mandatory option");

    let net = NodeNetwork::new(node_id);

    println!("aaaaaa");

    for _ in 0..100 {
        beaver_triple(&net);
    }

    println!("cccccc");
}
