use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

pub type NodeId = usize;

pub const NODE_NUM: usize = 3;
const NODE_ADDR: [(NodeId, &str); NODE_NUM] = [
    (0, "127.0.0.1:3000"),
    (1, "127.0.0.1:3001"),
    (2, "127.0.0.1:3002"),
];

pub struct NodeNetwork {
    pub self_id: NodeId,
    stream_read: HashMap<NodeId, TcpStream>,
    stream_write: HashMap<NodeId, TcpStream>,
}

impl NodeNetwork {
    pub fn new(self_id: NodeId) -> NodeNetwork {
        let port_self = NODE_ADDR
            .iter()
            .find(|&x| x.0 == self_id)
            .expect("node_id not found")
            .1
            .split(":")
            .collect::<Vec<&str>>()
            .get(1)
            .expect("Invalid addr")
            .parse::<u16>()
            .expect("Invalid port");

        let accept_thread = std::thread::spawn(move || establish_read_stream(port_self));

        let stream_write = establish_write_streams(self_id);
        let stream_read = accept_thread.join().unwrap();

        NodeNetwork {
            self_id,
            stream_read,
            stream_write,
        }
    }

    pub fn stream_left_read(&self) -> &TcpStream {
        let n = (self.self_id + NODE_NUM - 1) % NODE_NUM;
        self.stream_read.get(&n).expect("Invalid node_id")
    }

    pub fn stream_left_write(&self) -> &TcpStream {
        let n = (self.self_id + NODE_NUM - 1) % NODE_NUM;
        self.stream_write.get(&n).expect("Invalid node_id")
    }

    pub fn stream_right_read(&self) -> &TcpStream {
        let n = (self.self_id + 1) % NODE_NUM;
        self.stream_read.get(&n).expect("Invalid node_id")
    }

    pub fn stream_right_write(&self) -> &TcpStream {
        let n = (self.self_id + 1) % NODE_NUM;
        self.stream_write.get(&n).expect("Invalid node_id")
    }
}

fn establish_read_stream(self_port: u16) -> HashMap<NodeId, TcpStream> {
    let mut stream_read = HashMap::new();

    let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", self_port))
        .expect("Failed to TCP bind");

    for _ in 1..NODE_ADDR.len() {
        let mut s = listener.accept().expect("Failed to accept TCP connection");
        let mut node_id = [0u8; 2];
        s.0.read_exact(&mut node_id)
            .expect("Can't read node_id from connection");
        stream_read.insert(u16::from_le_bytes(node_id) as usize, s.0);
    }
    stream_read
}

fn establish_write_streams(self_id: NodeId) -> HashMap<NodeId, TcpStream> {
    let mut stream_write = HashMap::new();

    for node in NODE_ADDR {
        if node.0 == self_id {
            continue;
        }

        let mut stream = loop {
            match std::net::TcpStream::connect(node.1) {
                Ok(stream) => break stream,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(1000)),
            }
        };
        stream
            .write_all(&u16::to_le_bytes(self_id as u16))
            .unwrap_or_else(|_| panic!("Cant send node_id to {}", node.1));
        stream_write.insert(node.0, stream);
    }

    stream_write
}
