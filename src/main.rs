// Router 1 main.rs
//
// Run this on machine A. It will:
// - start a Babel node
// - advertise 10.0.1.0/24
// - log neighbor and route events

mod event;
mod neighbor;
mod node;
mod packet;
mod routing;
mod tlv;

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use event::Event;
use node::{AdvertisedPrefix, BabelConfig, BabelNode};

fn main() -> io::Result<()> {
    // Unique router-id for router 1
    let router_id: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0x01];

    // Pick the IPv4 address of the interface you want to use
    // For quick tests you can try Ipv4Addr::UNSPECIFIED, but on real machines
    // it's better to specify the actual interface IP.
    let iface = Ipv4Addr::UNSPECIFIED;
    let iface_index = 0; // if you later add multi-iface support you can change this

    let config = BabelConfig::new()
        .hello_interval_ms(1000)
        .ihu_interval_ms(4000)
        .update_interval_ms(10000)
        .with_advertised_prefix(AdvertisedPrefix {
            ae: 1,    // IPv4
            plen: 24, // 10.0.1.0/24
            prefix: vec![10, 0, 1],
            metric: 256,
        });

    let mut node = BabelNode::new_v4_multicast(iface, iface_index, router_id, config)?;
    println!(
        "[router1] Babel node started with router-id {:?}",
        router_id
    );

    loop {
        // Drive protocol once
        node.poll()?;

        // Drain and log events
        for ev in node.drain_events() {
            match ev {
                Event::NeighborUp(addr, _) => {
                    println!("[router1] Neighbor up: {addr}");
                }
                Event::NeighborDown(addr) => {
                    println!("[router1] Neighbor down: {addr}");
                }
                Event::RouteUpdated(key, route) => {
                    println!(
                        "[router1] Route updated: ae={} plen={} prefix={:?} via {:?} metric={} seqno={}",
                        key.ae, key.plen, key.prefix, route.next_hop, route.metric, route.seqno
                    );
                }
                Event::BestRouteChanged(key, route) => {
                    println!(
                        "[router1] *** Best route changed for ae={} plen={} prefix={:?}: {}",
                        key.ae,
                        key.plen,
                        key.prefix,
                        route.summary()
                    );
                }
            }
        }

        // Avoid busy spinning
        std::thread::sleep(Duration::from_millis(50));
    }
}
