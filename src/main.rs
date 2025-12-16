// src/main.rs

mod event;
mod neighbor;
mod node;
mod packet;
mod routing;
mod tlv;

use std::io;
use std::net::Ipv4Addr;

use node::{AdvertisedPrefix, BabelConfig, BabelNode};

fn main() -> io::Result<()> {
    // Example router-id – you’ll want something stable/derived from an address.
    let router_id: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    // Bind on all interfaces (for testing you might set this to a specific iface address)
    let iface = Ipv4Addr::UNSPECIFIED;
    let iface_index = 0;

    let config = BabelConfig::new()
        .hello_interval_ms(1000)
        .ihu_interval_ms(4000)
        .update_interval_ms(10000)
        .with_advertised_prefix(AdvertisedPrefix {
            ae: 1,    // IPv4
            plen: 24, // /24
            prefix: vec![192, 0, 2],
            metric: 256,
        });

    let mut node = BabelNode::new_v4_multicast(iface, iface_index, router_id, config)?;
    println!("Babel node started with router-id {:?}", router_id);

    node.run()
}
