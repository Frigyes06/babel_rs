// src/neighbor.rs
//! Neighbor tracking for a Babel node.
//!
//! This module handles:
//! - Tracking neighbors seen via Hello/IHU TLVs
//! - Reachability estimation (hello history bitmap)
//! - Link cost computation (rx/tx cost)
//! - Pruning stale neighbors
//!
//! It is the logical layer above raw TLV parsing but below route computation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Representation of a Babel neighbor.
///
/// A neighbor is keyed by the remote socket address and the interface
/// over which it was heard.
#[derive(Debug, Clone)]
pub struct Neighbor {
    /// Remote source address of Babel packets (IP + port).
    pub addr: SocketAddr,
    /// Local interface index on which this neighbor is reachable.
    pub iface_index: u32,

    /// Last Hello seqno received from this neighbor.
    pub last_hello_seqno: Option<u16>,
    /// Hello interval (ms) as advertised by the neighbor.
    pub hello_interval_ms: Option<u16>,
    /// History bitmask of Hello reception: LSB = most recent.
    pub hello_history: u16,

    /// Time of last received Hello.
    pub last_hello_rx: Option<Instant>,
    /// Time of last received IHU.
    pub last_ihu_rx: Option<Instant>,

    /// Neighbor’s advertised receive cost toward us (from IHU TLV).
    pub rxcost: Option<u16>,
    /// Our transmit cost toward this neighbor.
    pub txcost: Option<u16>,
}

impl Neighbor {
    /// Create a new neighbor with empty state.
    pub fn new(addr: SocketAddr, iface_index: u32) -> Self {
        Neighbor {
            addr,
            iface_index,
            last_hello_seqno: None,
            hello_interval_ms: None,
            hello_history: 0,
            last_hello_rx: None,
            last_ihu_rx: None,
            rxcost: None,
            txcost: None,
        }
    }

    /// Called when a Hello TLV is received from this neighbor.
    pub fn note_hello(&mut self, seqno: u16, interval_ms: u16, now: Instant) {
        self.last_hello_seqno = Some(seqno);
        self.hello_interval_ms = Some(interval_ms);
        self.last_hello_rx = Some(now);

        // Shift history, set LSB
        self.hello_history = (self.hello_history << 1) | 1;
    }

    /// Called when an IHU TLV is received from this neighbor.
    pub fn note_ihu(&mut self, rxcost: u16, _interval_ms: u16, now: Instant) {
        self.rxcost = Some(rxcost);
        self.last_ihu_rx = Some(now);
    }

    /// Set our transmit cost to this neighbor.
    pub fn set_txcost(&mut self, txcost: u16) {
        self.txcost = Some(txcost);
    }

    /// Compute link cost (naive):
    /// - If both rx/tx known → max(rx, tx)
    /// - Else if one known → that
    /// - Else None
    pub fn link_cost(&self) -> Option<u16> {
        match (self.rxcost, self.txcost) {
            (Some(rx), Some(tx)) => Some(rx.max(tx)),
            (Some(rx), None) => Some(rx),
            (None, Some(tx)) => Some(tx),
            _ => None,
        }
    }

    /// Whether the neighbor is reachable according to Hello history.
    pub fn is_reachable(&self, window: u8) -> bool {
        let k = window.min(16);
        let mask = if k == 16 { u16::MAX } else { (1u16 << k) - 1 };
        (self.hello_history & mask) != 0
    }

    /// Whether the neighbor has gone silent long enough to be considered stale.
    pub fn is_stale(&self, now: Instant, multiplier: u32) -> bool {
        let last = match self.last_hello_rx {
            Some(t) => t,
            None => return false,
        };

        let base_ms = self.hello_interval_ms.unwrap_or(4000) as u64;
        let max_silence = Duration::from_millis(base_ms * multiplier as u64);

        now.duration_since(last) > max_silence
    }
}

/// Table of all known neighbors.
#[derive(Debug, Default)]
pub struct NeighborTable {
    neighbors: HashMap<SocketAddr, Neighbor>,
}

impl NeighborTable {
    pub fn new() -> Self {
        NeighborTable {
            neighbors: HashMap::new(),
        }
    }

    pub fn all(&self) -> impl Iterator<Item = &Neighbor> {
        self.neighbors.values()
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<&Neighbor> {
        self.neighbors.get(addr)
    }

    pub fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut Neighbor> {
        self.neighbors.get_mut(addr)
    }

    fn ensure_neighbor(&mut self, addr: SocketAddr, iface_index: u32) -> &mut Neighbor {
        self.neighbors
            .entry(addr)
            .or_insert_with(|| Neighbor::new(addr, iface_index))
    }

    /// Update state according to a received Hello TLV.
    pub fn update_on_hello(
        &mut self,
        src: SocketAddr,
        iface_index: u32,
        seqno: u16,
        interval_ms: u16,
        now: Instant,
    ) {
        let n = self.ensure_neighbor(src, iface_index);
        n.note_hello(seqno, interval_ms, now);
    }

    /// Update state according to a received IHU TLV.
    pub fn update_on_ihu(
        &mut self,
        src: SocketAddr,
        iface_index: u32,
        rxcost: u16,
        interval_ms: u16,
        now: Instant,
    ) {
        let n = self.ensure_neighbor(src, iface_index);
        n.note_ihu(rxcost, interval_ms, now);
    }

    /// Set our txcost toward the neighbor.
    pub fn set_txcost(&mut self, addr: SocketAddr, iface_index: u32, txcost: u16) {
        let n = self.ensure_neighbor(addr, iface_index);
        n.set_txcost(txcost);
    }

    /// Remove all stale neighbors; returns how many were removed.
    pub fn prune_stale(&mut self, now: Instant, multiplier: u32) -> usize {
        let before = self.neighbors.len();
        self.neighbors.retain(|_, n| !n.is_stale(now, multiplier));
        before - self.neighbors.len()
    }

    pub fn prune_stale_with_addrs(&mut self, now: Instant, multiplier: u32) -> Vec<SocketAddr> {
        let mut removed = Vec::new();
        self.neighbors.retain(|addr, n| {
            if n.is_stale(now, multiplier) {
                removed.push(*addr);
                false
            } else {
                true
            }
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 6696)
    }

    #[test]
    fn hello_updates_neighbor() {
        let mut n = Neighbor::new(addr(), 1);
        let now = Instant::now();

        n.note_hello(5, 4000, now);
        assert_eq!(n.last_hello_seqno, Some(5));
        assert_eq!(n.hello_interval_ms, Some(4000));
        assert!(n.last_hello_rx.is_some());
        assert_eq!(n.hello_history & 1, 1);
    }

    #[test]
    fn hello_history_shifts_correctly() {
        let mut n = Neighbor::new(addr(), 1);
        let now = Instant::now();

        n.note_hello(1, 4000, now);
        n.note_hello(2, 4000, now);
        n.note_hello(3, 4000, now);

        assert_eq!(n.hello_history & 0b111, 0b111);
        assert!(n.is_reachable(3));
    }

    #[test]
    fn stale_neighbor_detection() {
        let mut n = Neighbor::new(addr(), 1);
        let now = Instant::now();

        n.note_hello(1, 1000, now);

        let later = now + Duration::from_millis(5000);
        assert!(n.is_stale(later, 3)); // 3 * 1000ms = 3s cutoff
    }

    #[test]
    fn link_cost_uses_max() {
        let mut n = Neighbor::new(addr(), 1);
        n.rxcost = Some(100);
        n.txcost = Some(150);
        assert_eq!(n.link_cost(), Some(150));
    }

    #[test]
    fn table_updates_neighbors() {
        let mut tbl = NeighborTable::new();
        let a = addr();
        let now = Instant::now();

        tbl.update_on_hello(a, 2, 42, 3000, now);
        tbl.update_on_ihu(a, 2, 200, 3000, now);

        let n = tbl.get(&a).unwrap();
        assert_eq!(n.last_hello_seqno, Some(42));
        assert_eq!(n.rxcost, Some(200));
        assert_eq!(n.iface_index, 2);
    }

    #[test]
    fn prune_removes_stale_neighbors() {
        let mut tbl = NeighborTable::new();
        let a = addr();
        let now = Instant::now();

        tbl.update_on_hello(a, 1, 1, 1000, now);
        let later = now + Duration::from_millis(5000);

        let removed = tbl.prune_stale(later, 3);
        assert_eq!(removed, 1);
        assert!(tbl.get(&a).is_none());
    }
}
