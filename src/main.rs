// src/main.rs
// Simple Babel node using TLV and Packet modules

// Declare modules from this crate
mod packet;
mod tlv;

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use packet::{BABEL_PORT, MULTICAST_V4_ADDR, Packet};

fn main() -> io::Result<()> {
    // Bind a UDP socket to all interfaces on the Babel port
    let socket = UdpSocket::bind(("0.0.0.0", BABEL_PORT))?;
    // Join the Babel IPv4 multicast group
    socket.join_multicast_v4(&MULTICAST_V4_ADDR, &Ipv4Addr::UNSPECIFIED)?;

    // Clone socket for the receiver thread
    let recv_socket = socket.try_clone()?;

    // Spawn receiver thread
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        loop {
            match Packet::recv(&recv_socket, &mut buf) {
                Ok((tlvs, src)) => {
                    println!("[Received {} TLVs from {}]", tlvs.len(), src);
                    for tlv in tlvs {
                        println!("  TLV: {:?}", tlv);
                    }
                }
                Err(e) => eprintln!("Receive error: {}", e),
            }
        }
    });

    // Periodically send Hello messages on the same socket
    let mut seqno: u16 = 1;
    let flags: u16 = 0; // no-special flags
    let interval_ms: u16 = 1000; // 1 second

    loop {
        // Build and serialize a Hello TLV
        let mut packet = Packet::new();
        packet.add_tlv(tlv::Tlv::Hello {
            flags: flags,
            seqno: seqno,
            interval: interval_ms,
            sub_tlvs: Vec::new(),
        });
        packet.add_tlv(tlv::Tlv::AckRequest {
            opaque: 255,
            interval: 200,
            sub_tlvs: Vec::new(),
        });
        packet.add_tlv(tlv::Tlv::PadN { n: 255 });
        //let hello_pkt = Packet::build_hello(flags, seqno, interval_ms);
        let payload = packet.to_bytes();
        let dest: SocketAddr = (MULTICAST_V4_ADDR, BABEL_PORT).into();

        // Send via the bound socket on 0.0.0.0
        match socket.send_to(&payload, dest) {
            Ok(n) => println!("Sent Hello #{} ({} bytes)", seqno, n),
            Err(e) => eprintln!("Send error: {}", e),
        }

        seqno = seqno.wrapping_add(1);
        thread::sleep(Duration::from_millis(interval_ms as u64));
    }
}
