//! babel-rs: a small Babel (RFC 8966) toolkit
//!
//! Main entry points:
//! - [`BabelNode`]: synchronous Babel node that sends Hellos, parses TLVs,
//!   tracks neighbors and a routing table.
//! - [`BabelConfig`]: configuration for [`BabelNode`].
//!
//! Lower-level modules are also exposed for advanced usage:
//! - [`tlv`]: TLV parsing/encoding
//! - [`packet`]: packet building, header + TLVs, multicast helpers
//! - [`neighbor`]: neighbor tracking and reachability
//! - [`routing`]: routing table and route selection

pub mod event;
pub mod neighbor;
pub mod node;
pub mod packet;
pub mod routing;
pub mod tlv;

pub use crate::event::Event;
pub use crate::neighbor::{Neighbor, NeighborTable};
pub use crate::node::{BabelConfig, BabelNode};
pub use crate::packet::{BABEL_PORT, MULTICAST_V4_ADDR, MULTICAST_V6_ADDR, Packet};
pub use crate::routing::{Route, RouteKey, RoutingTable};
pub use crate::tlv::{SubTlv, Tlv};
