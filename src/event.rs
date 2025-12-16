// src/event.rs
//! High-level events emitted by a Babel node.

use std::net::SocketAddr;

use crate::neighbor::Neighbor;
use crate::routing::{Route, RouteKey};

#[derive(Debug, Clone)]
pub enum Event {
    /// A neighbor was seen for the first time.
    NeighborUp(SocketAddr, Neighbor),

    /// A neighbor was removed as stale.
    NeighborDown(SocketAddr),

    /// A route was added or improved for this prefix.
    RouteUpdated(RouteKey, Route),

    /// The best route for a prefix changed.
    BestRouteChanged(RouteKey, Route),
}
