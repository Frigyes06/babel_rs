// src/main.rs

mod neighbor;
mod node;
mod packet;
mod routing;
mod tlv;

use std::io;
use std::net::Ipv4Addr;

use node::{BabelConfig, BabelNode};

fn main() -> io::Result<()> {
    // Example router-id – you’ll want something stable/derived from an address.
    let router_id: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    // Bind on all interfaces (for testing you might set this to a specific iface address)
    let iface = Ipv4Addr::UNSPECIFIED;
    let iface_index = 0;

    let config = BabelConfig {
        hello_interval_ms: 1000,
    };

    let mut node = BabelNode::new_v4_multicast(iface, iface_index, router_id, config)?;
    println!("Babel node started with router-id {:?}", router_id);

    node.run()
}
