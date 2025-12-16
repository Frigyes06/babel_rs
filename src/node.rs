// src/node.rs
//! High-level Babel node abstraction.
//!
//! This module builds on `tlv` and `packet` to provide a minimal
//! “Babel node” that can send Hellos, receive packets, and expose
//! parsed TLVs to the rest of the application.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::packet::{BABEL_PORT, MULTICAST_V4_ADDR, Packet};
use crate::tlv::Tlv;

/// Configuration for a simple Babel node.
#[derive(Debug, Clone)]
pub struct BabelConfig {
    /// Interval between Hello packets (in milliseconds).
    pub hello_interval_ms: u16,
}

impl Default for BabelConfig {
    fn default() -> Self {
        BabelConfig {
            hello_interval_ms: 4000, // 4s default, arbitrary but reasonable
        }
    }
}

/// A very simple, single-socket Babel node.
///
/// This is intentionally minimal: it focuses on sending/receiving packets
/// and tracking basic state (router-id, seqno, hello interval). Routing
/// tables, neighbor state, and OS route sync can be built on top of this.
pub struct BabelNode {
    /// Underlying UDP socket (usually bound to Babel port, possibly multicast).
    socket: UdpSocket,
    /// 64-bit router-id as used in Babel TLVs.
    router_id: [u8; 8],
    /// Current Hello sequence number (per interface).
    seqno: u16,
    /// Hello interval.
    hello_interval: Duration,
    /// Last time a Hello was sent (if any).
    last_hello: Option<Instant>,
}

impl BabelNode {
    /// Create a new Babel node bound to IPv4 multicast on the given interface.
    ///
    /// `iface` is the local IPv4 address of the interface to join the
    /// 224.0.0.111 group on. The socket is bound to 0.0.0.0:BABEL_PORT.
    pub fn new_v4_multicast(
        iface: Ipv4Addr,
        router_id: [u8; 8],
        config: BabelConfig,
    ) -> io::Result<Self> {
        let socket = Packet::bind_multicast_v4(iface)?;
        socket.set_nonblocking(true)?;
        Ok(BabelNode {
            socket,
            router_id,
            seqno: 1,
            hello_interval: Duration::from_millis(config.hello_interval_ms as u64),
            last_hello: None,
        })
    }

    /// Access the underlying socket (e.g., if you want to use select/poll/epoll).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Router-id used by this node.
    pub fn router_id(&self) -> [u8; 8] {
        self.router_id
    }

    /// Current Hello sequence number.
    pub fn seqno(&self) -> u16 {
        self.seqno
    }

    /// Send a multicast Hello on the bound interface.
    ///
    /// This builds a Hello TLV with:
    ///  - flags = 0
    ///  - seqno = node.seqno
    ///  - interval = configured hello_interval (ms)
    /// and sends it to the IPv4 Babel multicast group.
    pub fn send_hello(&mut self) -> io::Result<usize> {
        let flags: u16 = 0;
        let interval_ms: u16 = self
            .hello_interval
            .as_millis()
            .try_into()
            .unwrap_or(u16::MAX);

        let pkt = Packet::build_hello(flags, self.seqno, interval_ms);
        let dest: SocketAddr = (MULTICAST_V4_ADDR, BABEL_PORT).into();

        let sent = pkt.send_to(dest)?;
        self.seqno = self.seqno.wrapping_add(1);
        self.last_hello = Some(Instant::now());
        Ok(sent)
    }

    /// Check whether it's time to send the next Hello, and do so if needed.
    ///
    /// Returns:
    ///  - Ok(Some(bytes_sent)) if a Hello was sent,
    ///  - Ok(None) if not yet time,
    ///  - Err(_) if sending failed.
    pub fn maybe_send_hello(&mut self) -> io::Result<Option<usize>> {
        let now = Instant::now();
        match self.last_hello {
            None => {
                // No Hello sent yet; send immediately.
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

    /// Receive a single packet (non-blocking) and return parsed TLVs + source.
    ///
    /// If no data is available and the socket is non-blocking, returns
    /// `Ok(None)`.
    pub fn recv_once(&self) -> io::Result<Option<(Vec<Tlv>, SocketAddr)>> {
        let mut buf = [0u8; 1500];
        match Packet::recv(&self.socket, &mut buf) {
            Ok((tlvs, src)) => Ok(Some(tlvs, src)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Run a simple event loop:
    ///  - periodically send Hellos
    ///  - print any received TLVs
    ///
    /// This is mainly for demonstration / testing. A real daemon would
    /// integrate this into a proper reactor or async runtime.
    pub fn run(&mut self) -> io::Result<()> {
        loop {
            // 1) Maybe send a Hello
            if let Err(e) = self.maybe_send_hello() {
                eprintln!("[BabelNode] error sending Hello: {e}");
            }

            // 2) Try to receive a packet (non-blocking)
            match self.recv_once() {
                Ok(Some((tlvs, src))) => {
                    println!("[BabelNode] received {} TLVs from {src}", tlvs.len());
                    for tlv in tlvs {
                        println!("  TLV: {:?}", tlv);
                    }
                }
                Ok(None) => {
                    // No packet, that's fine.
                }
                Err(e) => {
                    eprintln!("[BabelNode] recv error: {e}");
                }
            }

            // 3) Sleep a bit to avoid busy loop
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
