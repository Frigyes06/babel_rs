// src/node.rs
//! High-level Babel node abstraction.
//!
//! This wraps Packet + TLV + NeighborTable + RoutingTable into a usable component
//! that can send hellos, IHUs, updates, receive packets, and maintain state.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::event::Event;
use crate::neighbor::NeighborTable;
use crate::packet::{BABEL_PORT, MULTICAST_V4_ADDR, Packet};
use crate::routing::{Route, RouteKey, RoutingTable};
use crate::tlv::Tlv;

/// A statically advertised prefix (e.g. "this node owns 192.0.2.0/24").
#[derive(Debug, Clone)]
pub struct AdvertisedPrefix {
    /// Address Encoding (1 = IPv4, 2 = IPv6, etc).
    pub ae: u8,
    /// Prefix length in bits.
    pub plen: u8,
    /// Raw prefix bytes (length = ceil(plen / 8)).
    pub prefix: Vec<u8>,
    /// Metric to advertise for this prefix.
    pub metric: u16,
}

/// Configuration for a Babel node.
#[derive(Debug, Clone)]
pub struct BabelConfig {
    pub hello_interval_ms: u16,
    pub ihu_interval_ms: u16,
    pub update_interval_ms: u16,
    pub advertised_prefixes: Vec<AdvertisedPrefix>,
}

impl Default for BabelConfig {
    fn default() -> Self {
        BabelConfig {
            hello_interval_ms: 4000,
            ihu_interval_ms: 4000,
            update_interval_ms: 10000,
            advertised_prefixes: Vec::new(),
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

    /// Set the IHU interval (in milliseconds).
    pub fn ihu_interval_ms(mut self, value: u16) -> Self {
        self.ihu_interval_ms = value;
        self
    }

    /// Set the Update interval (in milliseconds) for static prefixes.
    pub fn update_interval_ms(mut self, value: u16) -> Self {
        self.update_interval_ms = value;
        self
    }

    /// Add a statically advertised prefix.
    pub fn with_advertised_prefix(mut self, prefix: AdvertisedPrefix) -> Self {
        self.advertised_prefixes.push(prefix);
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

    ihu_interval: Duration,
    last_ihu: Option<Instant>,

    update_interval: Duration,
    last_update_advert: Option<Instant>,
    advertised_prefixes: Vec<AdvertisedPrefix>,

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

        let mut node = BabelNode {
            socket,
            router_id,
            seqno: 1,
            hello_interval: Duration::from_millis(config.hello_interval_ms as u64),
            last_hello: None,
            ihu_interval: Duration::from_millis(config.ihu_interval_ms as u64),
            last_ihu: None,
            update_interval: Duration::from_millis(config.update_interval_ms as u64),
            last_update_advert: None,
            advertised_prefixes: config.advertised_prefixes,
            iface_index,
            neighbors: NeighborTable::new(),
            routes: RoutingTable::new(),
            source_info: HashMap::new(),
            events: Vec::new(),
        };

        // Register our own advertised prefixes as local routes on startup.
        node.install_local_advertised_routes();

        Ok(node)
    }

    /// One non-blocking iteration of the node: send timers, receive, prune.
    pub fn poll(&mut self) -> io::Result<()> {
        if let Err(e) = self.maybe_send_hello() {
            eprintln!("[BabelNode] error sending hello: {e}");
        }

        if let Err(e) = self.maybe_send_ihus() {
            eprintln!("[BabelNode] error sending IHU: {e}");
        }

        if let Err(e) = self.maybe_send_updates() {
            eprintln!("[BabelNode] error sending Update: {e}");
        }

        if let Some((tlvs, src)) = self.recv_once()? {
            self.handle_tlvs_from(src, &tlvs);
        }

        // Neighbor pruning => NeighborDown events
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

    pub fn seqno(&self) -> u16 {
        self.seqno
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

    /// Send IHUs to all known neighbors.
    fn send_ihus(&mut self) -> io::Result<usize> {
        let mut total_bytes = 0usize;

        let interval_ms: u16 = self.ihu_interval.as_millis().try_into().unwrap_or(u16::MAX);
        let rxcost: u16 = 256;

        for n in self.neighbors.all() {
            let ip = n.addr.ip();
            let (ae, addr_opt) = match ip {
                IpAddr::V4(v4) => (1u8, Some(IpAddr::V4(v4))),
                IpAddr::V6(v6) => (2u8, Some(IpAddr::V6(v6))),
            };

            let pkt = Packet::build_ihu(ae, rxcost, interval_ms, addr_opt);
            total_bytes += pkt.send_to(n.addr)?;
        }

        Ok(total_bytes)
    }

    /// Send IHUs if enough time has passed.
    pub fn maybe_send_ihus(&mut self) -> io::Result<Option<usize>> {
        if self.neighbors.all().next().is_none() {
            return Ok(None);
        }

        let now = Instant::now();
        match self.last_ihu {
            None => {
                let n = self.send_ihus()?;
                self.last_ihu = Some(now);
                Ok(Some(n))
            }
            Some(last) if now.duration_since(last) >= self.ihu_interval => {
                let n = self.send_ihus()?;
                self.last_ihu = Some(now);
                Ok(Some(n))
            }
            Some(_) => Ok(None),
        }
    }

    /// Send Updates for statically configured prefixes (multicast).
    fn send_static_updates(&mut self) -> io::Result<usize> {
        if self.advertised_prefixes.is_empty() {
            return Ok(0);
        }

        let mut total_bytes = 0usize;
        let interval_ms: u16 = self
            .update_interval
            .as_millis()
            .try_into()
            .unwrap_or(u16::MAX);

        for p in &self.advertised_prefixes {
            let pkt = Packet::build_update(
                p.ae,
                0, // flags
                p.plen,
                0, // omitted
                interval_ms,
                self.seqno,
                p.metric,
                p.prefix.clone(),
            );
            let dest: SocketAddr = (MULTICAST_V4_ADDR, BABEL_PORT).into();
            total_bytes += pkt.send_to(dest)?;
        }

        self.seqno = self.seqno.wrapping_add(1);
        Ok(total_bytes)
    }

    /// Send static Updates if enough time has passed.
    pub fn maybe_send_updates(&mut self) -> io::Result<Option<usize>> {
        if self.advertised_prefixes.is_empty() {
            return Ok(None);
        }

        let now = Instant::now();
        match self.last_update_advert {
            None => {
                let n = self.send_static_updates()?;
                self.last_update_advert = Some(now);
                Ok(Some(n))
            }
            Some(last) if now.duration_since(last) >= self.update_interval => {
                let n = self.send_static_updates()?;
                self.last_update_advert = Some(now);
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

    /// Helper: install a route into the table and emit RouteUpdated / BestRouteChanged events.
    fn install_route_and_emit_events(&mut self, key: RouteKey, route: Route) {
        let old_best = self.routes.best_route(&key).cloned();

        let changed = self.routes.install_or_update(route);
        if !changed {
            return;
        }

        if let Some(best) = self.routes.best_route(&key).cloned() {
            // RouteUpdated: some path for this key changed (we expose the current best).
            self.push_event(Event::RouteUpdated(key.clone(), best.clone()));

            // Did the best route actually change?
            let best_changed = match old_best {
                None => true,
                Some(ref old) => {
                    old.metric != best.metric
                        || old.seqno != best.seqno
                        || old.router_id != best.router_id
                        || old.next_hop != best.next_hop
                }
            };

            if best_changed {
                self.push_event(Event::BestRouteChanged(key.clone(), best.clone()));
            }

            println!(
                "[BabelNode] new/updated route installed; best now: {}",
                best.summary()
            );
        }
    }

    /// Register our own advertised prefixes as local routes.
    fn install_local_advertised_routes(&mut self) {
        // Clone prefixes so we don't hold an immutable borrow of `self`
        // while calling a `&mut self` method.
        let prefixes = self.advertised_prefixes.clone();
        let router_id = self.router_id;
        let iface_index = self.iface_index;
        let seqno = self.seqno; // starting local seqno for our own routes

        for p in prefixes {
            let key = RouteKey {
                ae: p.ae,
                plen: p.plen,
                prefix: p.prefix.clone(),
            };

            let route = Route {
                key: key.clone(),
                metric: p.metric,
                seqno,
                router_id,
                next_hop: None,
                iface_index,
            };

            self.install_route_and_emit_events(key, route);
        }
    }

    /// Process TLVs received from a given source, emitting events as needed.
    pub fn handle_tlvs_from(&mut self, src: SocketAddr, tlvs: &[Tlv]) {
        let now = Instant::now();
        let src_ip = src.ip();
        let iface_index = self.iface_index;

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
                    let sinfo = self.source_info.entry(src).or_default();
                    sinfo.router_id = Some(*router_id);
                }

                Tlv::NextHop { ae: _, addr, .. } => {
                    let sinfo = self.source_info.entry(src).or_default();
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
                    // This is where we register new routes from *remote routers*.
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

                        let route = Route {
                            key: key.clone(),
                            metric: *metric,
                            seqno: *seqno,
                            router_id,
                            next_hop: nexthop_opt,
                            iface_index,
                        };

                        self.install_route_and_emit_events(key, route);
                    } else {
                        eprintln!(
                            "[BabelNode] ignoring Update from {}: unknown router-id",
                            src
                        );
                    }
                }

                Tlv::RouteRequest { .. } => {
                    // TODO: respond with matching Update(s)
                }

                Tlv::SeqnoRequest { .. } => {
                    // TODO: respond with appropriate Update
                }

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
            self.poll()?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
