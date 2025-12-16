// src/node.rs
//! High-level Babel node abstraction.
//!
//! This wraps Packet + TLV + NeighborTable into a usable component
//! that can send hellos, receive packets, and maintain neighbor state.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket}; // + IpAddr
use std::time::{Duration, Instant};

use crate::event::Event;
use crate::neighbor::NeighborTable;
use crate::packet::{BABEL_PORT, MULTICAST_V4_ADDR, Packet};
use crate::routing::{Route, RouteKey, RoutingTable};
use crate::tlv::Tlv;

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

impl BabelConfig {
    /// Create a new config with sensible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hello interval (in milliseconds).
    pub fn hello_interval_ms(mut self, value: u16) -> Self {
        self.hello_interval_ms = value;
        self
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
    pub routes: RoutingTable,
    source_info: HashMap<SocketAddr, SourceInfo>,
    events: Vec<Event>,
}

#[derive(Debug, Default, Clone)]
struct SourceInfo {
    router_id: Option<[u8; 8]>,
    next_hop: Option<IpAddr>,
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
            routes: RoutingTable::new(),
            source_info: HashMap::new(),
            events: Vec::new(),
        })
    }

    pub fn poll(&mut self) -> io::Result<()> {
        if let Err(e) = self.maybe_send_hello() {
            eprintln!("[BabelNode] error sending hello: {e}");
        }

        if let Some((tlvs, src)) = self.recv_once()? {
            self.handle_tlvs_from(src, &tlvs);
        }

        // Simple neighbor pruning hook
        let now = Instant::now();
        for addr in self.neighbors.prune_stale_with_addrs(now, 3) {
            self.push_event(Event::NeighborDown(addr));
        }

        Ok(())
    }

    /// Current router-id of this node.
    pub fn router_id(&self) -> [u8; 8] {
        self.router_id
    }

    /// Immutable view of all known neighbors.
    pub fn neighbors(&self) -> impl Iterator<Item = &crate::neighbor::Neighbor> {
        self.neighbors.all()
    }

    /// Immutable view of all known routes.
    pub fn routes(&self) -> &[crate::routing::Route] {
        self.routes.all()
    }

    /// Convenience: best route for a given key, if any.
    pub fn best_route(&self, key: &crate::routing::RouteKey) -> Option<&crate::routing::Route> {
        self.routes.best_route(key)
    }

    pub fn seqno(&self) -> u16 {
        self.seqno
    }

    fn source_info_mut(&mut self, src: SocketAddr) -> &mut SourceInfo {
        self.source_info.entry(src).or_default()
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
        let src_ip = src.ip();
        let iface_index = self.iface_index; // copy, so we don't borrow self for this

        for tlv in tlvs {
            match tlv {
                Tlv::Hello {
                    seqno, interval, ..
                } => {
                    let is_new = self.neighbors.get(&src).is_none();
                    self.neighbors
                        .update_on_hello(src, iface_index, *seqno, *interval, now);

                    if is_new {
                        if let Some(n) = self.neighbors.get(&src).cloned() {
                            self.push_event(Event::NeighborUp(src, n));
                        }
                    }
                }

                Tlv::Ihu {
                    rxcost, interval, ..
                } => {
                    self.neighbors
                        .update_on_ihu(src, iface_index, *rxcost, *interval, now);
                }

                Tlv::RouterId { router_id, .. } => {
                    // Short-lived mutable borrow of source_info
                    let sinfo = self.source_info.entry(src).or_default();
                    sinfo.router_id = Some(*router_id);
                }

                Tlv::NextHop { ae: _, addr, .. } => {
                    let sinfo = self.source_info.entry(src).or_default();
                    // If no explicit nexthop address, fall back to src IP.
                    sinfo.next_hop = addr.or(Some(src_ip));
                }

                Tlv::Update {
                    ae,
                    flags: _,
                    plen,
                    omitted: _,
                    interval: _,
                    seqno,
                    metric,
                    prefix,
                    sub_tlvs: _,
                } => {
                    // Look up router-id and nexthop learned for this source.
                    let router_id_opt = self.source_info.get(&src).and_then(|si| si.router_id);

                    if let Some(router_id) = router_id_opt {
                        let nexthop_opt = self
                            .source_info
                            .get(&src)
                            .and_then(|si| si.next_hop)
                            .or(Some(src_ip));

                        let key = RouteKey {
                            ae: *ae,
                            plen: *plen,
                            prefix: prefix.clone(),
                        };

                        // Best route before we touch the table
                        let old_best = self.routes.best_route(&key).cloned();

                        // Clone key because we move it into Route but still want
                        // to use it later for lookups and events.
                        let route = Route {
                            key: key.clone(),
                            metric: *metric,
                            seqno: *seqno,
                            router_id,
                            next_hop: nexthop_opt,
                            iface_index,
                        };

                        let changed = self.routes.install_or_update(route);
                        if changed {
                            if let Some(best) = self.routes.best_route(&key).cloned() {
                                // RouteUpdated: this prefix/path changed
                                self.push_event(Event::RouteUpdated(key.clone(), best.clone()));

                                // Did the best route for this prefix change?
                                let best_changed = match old_best {
                                    None => true,
                                    Some(ref old) => {
                                        old.metric != best.metric || old.seqno != best.seqno
                                    }
                                };

                                if best_changed {
                                    self.push_event(Event::BestRouteChanged(
                                        key.clone(),
                                        best.clone(),
                                    ));
                                }

                                println!(
                                    "[BabelNode] new/updated route installed; best now: {}",
                                    best.summary()
                                );
                            }
                        }
                    } else {
                        eprintln!(
                            "[BabelNode] ignoring Update from {}: unknown router-id",
                            src
                        );
                    }
                }

                // For now we ignore these; later we can implement responses.
                Tlv::RouteRequest { .. } => {}
                Tlv::SeqnoRequest { .. } => {}

                _ => {
                    // Other TLVs currently ignored.
                }
            }
        }
    }

    fn push_event(&mut self, ev: Event) {
        self.events.push(ev);
    }

    /// Take and return all pending events since the last call.
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Convenience: poll the node and return any events produced.
    pub fn poll_with_events(&mut self) -> io::Result<Vec<Event>> {
        self.poll()?;
        Ok(self.drain_events())
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
