//! How the engine talks to other nodes, abstracted so that the same guardian/publisher logic runs
//! over libp2p (`alp-grid-net`) and inside the in-memory simulator (`alp-grid-sim`).

use std::fmt;

use async_trait::async_trait;

use crate::ids::Position;
use crate::keys::PublicKey;
use crate::wire::{AtlasRequest, AtlasResponse};

/// Network prefix used by the diversity rule (/16 IPv4 = 2 bytes, /48 IPv6 = 6 bytes, empty = unknown).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct NetPrefix(pub Vec<u8>);

impl NetPrefix {
    pub fn of(ip: &std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => NetPrefix(v4.octets()[..2].to_vec()),
            std::net::IpAddr::V6(v6) => NetPrefix(v6.octets()[..6].to_vec()),
        }
    }
}

/// A node as the engine sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeRef {
    pub pubkey: PublicKey,
    pub operator: PublicKey,
    pub prefix: NetPrefix,
}

impl NodeRef {
    pub fn position(&self) -> Position {
        Position::of_node(&self.pubkey)
    }
}

#[derive(Debug, Clone)]
pub enum TransportError {
    Timeout,
    Unreachable(String),
    Protocol(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Timeout => write!(f, "timeout"),
            TransportError::Unreachable(s) => write!(f, "unreachable: {s}"),
            TransportError::Protocol(s) => write!(f, "protocol: {s}"),
        }
    }
}

impl std::error::Error for TransportError {}

#[async_trait]
pub trait Transport: Send + Sync {
    /// This node.
    fn me(&self) -> NodeRef;
    /// The `k` known nodes closest to `key` in the XOR space, this node included when it qualifies.
    async fn closest(&self, key: &Position, k: usize) -> Vec<NodeRef>;
    /// All nodes currently known (routing table).
    fn known(&self) -> Vec<NodeRef>;
    /// Send one request and wait for its answer.
    async fn request(&self, to: &NodeRef, req: AtlasRequest) -> Result<AtlasResponse, TransportError>;
}

/// What a transport calls when a request arrives from the network.
pub trait InboundHandler: Send + Sync {
    fn handle(&self, from: Option<NodeRef>, req: AtlasRequest) -> AtlasResponse;
}
