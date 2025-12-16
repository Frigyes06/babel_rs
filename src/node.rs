// src/node.rs
//! High-level Babel node abstraction.
//!
//! This wraps Packet + TLV + NeighborTable into a usable component
//! that can send hellos, receive packets, and maintain neighbor state.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::neighbor::NeighborTable;
use crate::packet::{BABEL_PORT, MULTICAST_V4_ADDR, Packet};
use crate::tlv::Tlv;

/// Configuration for a Babel node.
#[derive(Debug, Clone)]
pub struct BabelConfig {
    pub hello_interval_ms: u16,
}

impl Default for BabelConfig {
    fn default() -> Self {
        BabelConfig {
            hello_interval_ms: 4000,
        }
    }
}

/// A simple synchronous Babel node.
pub struct BabelNode {
    socket: UdpSocket,
    router_id: [u8; 8],
    seqno: u16,
    hello_interval: Duration,
    last_hello: Option<Instant>,
    pub iface_index: u32,
    pub neighbors: NeighborTable,
}

impl BabelNode {
    /// Create a Babel node joined to IPv4 multicast on the given interface.
    pub fn new_v4_multicast(
        iface_addr: Ipv4Addr,
        iface_index: u32,
        router_id: [u8; 8],
        config: BabelConfig,
    ) -> io::Result<Self> {
        let socket = Packet::bind_multicast_v4(iface_addr)?;
        socket.set_nonblocking(true)?;

        Ok(BabelNode {
            socket,
            router_id,
            seqno: 1,
            hello_interval: Duration::from_millis(config.hello_interval_ms as u64),
            last_hello: None,
            iface_index,
            neighbors: NeighborTable::new(),
        })
    }

    pub fn router_id(&self) -> [u8; 8] {
        self.router_id
    }

    pub fn seqno(&self) -> u16 {
        self.seqno
    }

    /// Send a multicast Hello.
    pub fn send_hello(&mut self) -> io::Result<usize> {
        let flags: u16 = 0;
        let interval_ms: u16 = self
            .hello_interval
            .as_millis()
            .try_into()
            .unwrap_or(u16::MAX);

        let pkt = Packet::build_hello(flags, self.seqno, interval_ms);
        let dest: SocketAddr = (MULTICAST_V4_ADDR, BABEL_PORT).into();

        let sent_bytes = pkt.send_to(dest)?;
        self.seqno = self.seqno.wrapping_add(1);
        self.last_hello = Some(Instant::now());
        Ok(sent_bytes)
    }

    /// Send a Hello if enough time has passed.
    pub fn maybe_send_hello(&mut self) -> io::Result<Option<usize>> {
        let now = Instant::now();
        match self.last_hello {
            None => {
                let n = self.send_hello()?;
                Ok(Some(n))
            }
            Some(last) if now.duration_since(last) >= self.hello_interval => {
                let n = self.send_hello()?;
                Ok(Some(n))
            }
            Some(_) => Ok(None),
        }
    }

    /// Receive one packet (non-blocking).
    pub fn recv_once(&self) -> io::Result<Option<(Vec<Tlv>, SocketAddr)>> {
        let mut buf = [0u8; 1500];

        match Packet::recv(&self.socket, &mut buf) {
            Ok((tlvs, src)) => Ok(Some((tlvs, src))),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Process TLVs received from a given source.
    pub fn handle_tlvs_from(&mut self, src: SocketAddr, tlvs: &[Tlv]) {
        let now = Instant::now();

        for tlv in tlvs {
            match tlv {
                Tlv::Hello {
                    seqno, interval, ..
                } => {
                    self.neighbors
                        .update_on_hello(src, self.iface_index, *seqno, *interval, now);
                }

                Tlv::Ihu {
                    rxcost, interval, ..
                } => {
                    self.neighbors
                        .update_on_ihu(src, self.iface_index, *rxcost, *interval, now);
                }

                _ => {
                    // Future: updates, router-ids, seqno-requests, etc.
                }
            }
        }
    }

    /// Simple blocking event loop for a Babel node (demo mode).
    pub fn run(&mut self) -> io::Result<()> {
        println!("[BabelNode] running, router-id = {:?}", self.router_id);

        loop {
            // 1) Send hello if needed
            if let Err(e) = self.maybe_send_hello() {
                eprintln!("[BabelNode] error sending hello: {e}");
            }

            // 2) Receive packets
            if let Some((tlvs, src)) = self.recv_once()? {
                self.handle_tlvs_from(src, &tlvs);
            }

            // 3) Sleep a little so we don't busy-spin
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
