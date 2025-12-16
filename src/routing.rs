// src/routing.rs
//! Simple routing table and route selection for Babel.

use std::net::IpAddr;

/// Key identifying a prefix in Babel (AE + prefix length + bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub ae: u8,
    pub plen: u8,
    /// Raw prefix bytes as in the TLV (already de-omitted).
    pub prefix: Vec<u8>,
}

/// One route entry learned via Babel Update.
#[derive(Debug, Clone)]
pub struct Route {
    pub key: RouteKey,
    pub metric: u16,
    pub seqno: u16,
    pub router_id: [u8; 8],
    pub next_hop: Option<IpAddr>,
    pub iface_index: u32,
}

impl Route {
    /// Return a short human-ish description for debugging/logging.
    pub fn summary(&self) -> String {
        format!(
            "ae={} plen={} metric={} seqno={} router_id={:02x?} nexthop={:?} iface={}",
            self.key.ae,
            self.key.plen,
            self.metric,
            self.seqno,
            self.router_id,
            self.next_hop,
            self.iface_index
        )
    }
}

/// In-memory routing table with naive best-route selection.
#[derive(Debug, Default)]
pub struct RoutingTable {
    routes: Vec<Route>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable { routes: Vec::new() }
    }

    /// Return a slice of all routes.
    pub fn all(&self) -> &[Route] {
        &self.routes
    }

    /// Return an iterator of routes matching the given key.
    pub fn routes_for(&self, key: &RouteKey) -> impl Iterator<Item = &Route> {
        self.routes.iter().filter(move |r| &r.key == key)
    }

    /// Best route for a given key, if any (lower metric, then higher seqno).
    pub fn best_route(&self, key: &RouteKey) -> Option<&Route> {
        self.routes_for(key).max_by(|a, b| {
            use std::cmp::Ordering;
            match a.metric.cmp(&b.metric).reverse() {
                Ordering::Equal => a.seqno.cmp(&b.seqno),
                other => other,
            }
        })
    }

    /// Install or update a route.
    ///
    /// Returns true if the table changed, false if the new route was worse.
    pub fn install_or_update(&mut self, new_route: Route) -> bool {
        if let Some(existing) = self.routes.iter_mut().find(|r| {
            r.key == new_route.key
                && r.router_id == new_route.router_id
                && r.next_hop == new_route.next_hop
                && r.iface_index == new_route.iface_index
        }) {
            if Self::is_better(&new_route, existing) {
                *existing = new_route;
                true
            } else {
                false
            }
        } else {
            self.routes.push(new_route);
            true
        }
    }

    /// Remove all routes that came from a given router-id.
    pub fn remove_by_router(&mut self, router_id: [u8; 8]) -> usize {
        let before = self.routes.len();
        self.routes.retain(|r| r.router_id != router_id);
        before - self.routes.len()
    }

    fn is_better(new: &Route, old: &Route) -> bool {
        if new.metric < old.metric {
            true
        } else if new.metric > old.metric {
            false
        } else {
            new.seqno > old.seqno
        }
    }
}
