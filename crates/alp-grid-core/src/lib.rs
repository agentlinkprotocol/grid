//! Core of The Grid: everything that must be bit-identical across every node and every SDK.
//!
//! * [`canon`]: canonical CBOR encoding rules and domain-separated signing hashes.
//! * [`keys`]: Ed25519 key wrappers and fixed-size byte newtypes.
//! * [`ids`]: agent, node and operator identifiers, Kademlia positions, identity proof of work.
//! * [`types`]: the signed objects of the Atlas (Card, Ephemeral, Revocation, OperatorCert, Receipt, LedgerEntry).
//! * [`wire`]: request/response payloads of the `/alp/atlas/*` protocols.
//! * [`params`]: v1 network parameters.
//! * [`validate`]: structural and cryptographic validation shared by publishers and guardians.

pub mod canon;
pub mod error;
pub mod ids;
pub mod keys;
pub mod params;
pub mod time;
pub mod transport;
pub mod types;
pub mod validate;
pub mod wire;

pub use error::{Error, Result};
pub use ids::{AgentId, Position};
pub use keys::{Bytes16, Bytes32, Bytes64, Keypair, PublicKey};
pub use types::*;
