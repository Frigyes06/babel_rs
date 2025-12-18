// src/packet.rs
// Babel packet construction and I/O helpers with RFC-compliant builders,
// multicast support, and integration tests

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

use crate::tlv::Tlv;

/// Babel default port and multicast group addresses
pub const BABEL_PORT: u16 = 6696;
pub const MULTICAST_V4_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 111);
pub const MULTICAST_V6_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0006);

/// A Babel packet: a sequence of TLVs to be sent via UDP
pub struct Packet {
    tlvs: Vec<Tlv>,
}

impl Packet {
    pub const BABEL_MAGIC: u8 = 42;
    pub const BABEL_VERSION: u8 = 2;

    pub fn new() -> Self {
        Packet { tlvs: Vec::new() }
    }

    pub fn with_tlvs(tlvs: Vec<Tlv>) -> Self {
        Packet { tlvs }
    }

    pub fn add_tlv(&mut self, tlv: Tlv) {
        self.tlvs.push(tlv);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let body: Vec<u8> = self.tlvs.iter().flat_map(|t| t.to_bytes()).collect();
        let body_len = body.len() as u16;

        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(Self::BABEL_MAGIC);
        buf.push(Self::BABEL_VERSION);
        buf.extend_from_slice(&body_len.to_be_bytes());
        buf.extend_from_slice(&body);

        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        let tlv_slice =
            if buf.len() >= 4 && buf[0] == Self::BABEL_MAGIC && buf[1] == Self::BABEL_VERSION {
                let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                if 4 + body_len > buf.len() {
                    return Err("Babel body length exceeds buffer".into());
                }
                &buf[4..4 + body_len]
            } else {
                buf
            };

        let tlvs = Tlv::parse_all(tlv_slice)?;
        Ok(Packet { tlvs })
    }

    pub fn magic() -> u8 {
        Self::BABEL_MAGIC
    }

    pub fn version() -> u8 {
        Self::BABEL_VERSION
    }

    pub fn body_len(&self) -> u16 {
        self.tlvs.iter().map(|t| t.to_bytes().len()).sum::<usize>() as u16
    }

    pub fn send_to<A: ToSocketAddrs>(&self, addr: A) -> io::Result<usize> {
        let buf = self.to_bytes();
        let mut last_err = None;
        for target in addr.to_socket_addrs()? {
            let socket = if target.is_ipv4() {
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?
            } else {
                UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?
            };
            if let Err(e) = socket.send_to(&buf, target) {
                last_err = Some(e);
                continue;
            } else {
                return Ok(buf.len());
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "send_to failed")))
    }

    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
        UdpSocket::bind(addr).and_then(|s| {
            s.set_nonblocking(false)?;
            Ok(s)
        })
    }

    pub fn recv(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(Vec<Tlv>, SocketAddr)> {
        let (amt, src) = socket.recv_from(buf)?;
        let pkt = Packet::from_bytes(&buf[..amt])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok((pkt.tlvs, src))
    }

    //=== RFC-compliant convenience builders ===

    pub fn build_pad1() -> Self {
        Packet::with_tlvs(vec![Tlv::Pad1])
    }

    pub fn build_padn(n: u8) -> Self {
        Packet::with_tlvs(vec![Tlv::PadN { n }])
    }

    pub fn build_ack_request(opaque: u16, interval: u16) -> Self {
        Packet::with_tlvs(vec![Tlv::AckRequest {
            opaque,
            interval,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_ack(opaque: u16) -> Self {
        Packet::with_tlvs(vec![Tlv::Ack {
            opaque,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_hello(flags: u16, seqno: u16, interval: u16) -> Self {
        Packet::with_tlvs(vec![Tlv::Hello {
            flags,
            seqno,
            interval,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_ihu(ae: u8, rxcost: u16, interval: u16, addr: Option<IpAddr>) -> Self {
        Packet::with_tlvs(vec![Tlv::Ihu {
            ae,
            rxcost,
            interval,
            addr,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_router_id(router_id: [u8; 8]) -> Self {
        Packet::with_tlvs(vec![Tlv::RouterId {
            router_id,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_next_hop(ae: u8, addr: Option<IpAddr>) -> Self {
        Packet::with_tlvs(vec![Tlv::NextHop {
            ae,
            addr,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_update(
        ae: u8,
        flags: u8,
        plen: u8,
        omitted: u8,
        interval: u16,
        seqno: u16,
        metric: u16,
        prefix: Vec<u8>,
    ) -> Self {
        Packet::with_tlvs(vec![Tlv::Update {
            ae,
            flags,
            plen,
            omitted,
            interval,
            seqno,
            metric,
            prefix,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_route_request(ae: u8, plen: u8, prefix: Vec<u8>) -> Self {
        Packet::with_tlvs(vec![Tlv::RouteRequest {
            ae,
            plen,
            prefix,
            sub_tlvs: Vec::new(),
        }])
    }

    pub fn build_seqno_request(
        ae: u8,
        plen: u8,
        seqno: u16,
        hop_count: u8,
        router_id: [u8; 8],
        prefix: Vec<u8>,
    ) -> Self {
        Packet::with_tlvs(vec![Tlv::SeqnoRequest {
            ae,
            plen,
            seqno,
            hop_count,
            router_id,
            prefix,
            sub_tlvs: Vec::new(),
        }])
    }

    //=== Multicast support ===

    pub fn bind_multicast_v4(interface: Ipv4Addr) -> io::Result<UdpSocket> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, BABEL_PORT))?;
        socket.join_multicast_v4(&MULTICAST_V4_ADDR, &interface)?;
        // Don't receive our own multicast packets.
        socket.set_multicast_loop_v4(false)?;
        Ok(socket)
    }

    pub fn bind_multicast_v6(interface_index: u32) -> io::Result<UdpSocket> {
        let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, BABEL_PORT))?;
        socket.join_multicast_v6(&MULTICAST_V6_ADDR, interface_index)?;
        Ok(socket)
    }
}

/// Integration tests for packet construction, send/receive, and multicast
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_build_and_serialize() {
        let pkt = Packet::build_hello(0x0001, 42, 1000);
        let bytes = pkt.to_bytes();
        assert!(bytes.len() > 4); // header + at least one TLV
    }

    #[test]
    fn test_send_recv_local() {
        let server = Packet::bind(("127.0.0.1", 0)).expect("bind failed");
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let client = Packet::build_pad1();
            client.send_to(addr).expect("send failed");
        });
        let mut buf = [0u8; 1500];
        let (tlvs, _src) = Packet::recv(&server, &mut buf).expect("recv failed");
        assert_eq!(tlvs, vec![Tlv::Pad1]);
        handle.join().unwrap();
    }

    #[test]
    fn test_multicast_v4_binding() {
        let iface = Ipv4Addr::new(127, 0, 0, 1);
        let socket = Packet::bind_multicast_v4(iface).expect("multicast bind failed");
        let local = socket.local_addr().unwrap();
        assert_eq!(local.port(), BABEL_PORT);
    }

    #[test]
    fn test_multicast_v6_binding() {
        let socket = Packet::bind_multicast_v6(0).expect("multicast v6 bind failed");
        let local = socket.local_addr().unwrap();
        assert_eq!(local.port(), BABEL_PORT);
    }
}
