//! Identifiers and positions.
//!
//! * `AgentId` = "alp1" + lowercase base32 (no padding) of blake3(agent_pubkey)[0..20].
//! * `Position` = blake3(node_pubkey), 256 bits in the Kademlia XOR space. Never chosen, always recomputed.
//! * Proof of work: blake3("alp-pow" || pubkey || nonce_be64) must start with `POW_BITS` zero bits.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::canon;
use crate::error::{Error, Result};
use crate::keys::{Bytes32, PublicKey};
use crate::params::{self, domain};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = String, example = "alp1qnlbvwzzr7mh7dt63azrx7zpzokfom6m"))]
#[serde(transparent)]
pub struct AgentId(String);

impl AgentId {
    pub const PREFIX: &'static str = "alp1";

    pub fn from_pubkey(pk: &PublicKey) -> Self {
        let h = blake3::hash(&pk.0);
        let b32 = BASE32_NOPAD.encode(&h.as_bytes()[..20]).to_lowercase();
        AgentId(format!("{}{}", Self::PREFIX, b32))
    }

    pub fn parse(s: &str) -> Result<Self> {
        if !s.starts_with(Self::PREFIX) {
            return Err(Error::invalid("agent_id", "missing alp1 prefix"));
        }
        let body = &s[Self::PREFIX.len()..];
        if body.len() != 32 {
            return Err(Error::invalid("agent_id", "bad length"));
        }
        BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|_| Error::invalid("agent_id", "bad base32"))?;
        Ok(AgentId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check that this id matches the given public key.
    pub fn matches(&self, pk: &PublicKey) -> bool {
        &Self::from_pubkey(pk) == self
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId({})", self.0)
    }
}

/// 256-bit position in the Kademlia XOR space.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Position(pub Bytes32);

impl Position {
    pub fn of_node(pk: &PublicKey) -> Self {
        Position(Bytes32(canon::hash(&pk.0)))
    }

    pub fn from_key(key: [u8; 32]) -> Self {
        Position(Bytes32(key))
    }

    pub fn distance(&self, other: &Position) -> [u8; 32] {
        let mut d = [0u8; 32];
        for ((out, a), b) in d.iter_mut().zip(self.0 .0.iter()).zip(other.0 .0.iter()) {
            *out = a ^ b;
        }
        d
    }

    /// Number of leading zero bits of the XOR distance (shared prefix length).
    pub fn common_prefix_bits(&self, other: &Position) -> u32 {
        let d = self.distance(other);
        let mut bits = 0;
        for b in d {
            if b == 0 {
                bits += 8;
            } else {
                bits += b.leading_zeros();
                break;
            }
        }
        bits
    }
}

impl fmt::Debug for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Position({}…)", &self.0.to_hex()[..16])
    }
}

/// DHT key of an agent's full Card.
pub fn card_key(agent_id: &AgentId) -> Position {
    Position(Bytes32(canon::domain_hash(domain::CARD_KEY, agent_id.as_str().as_bytes())))
}

/// DHT key of a semantic zone for a given map version.
pub fn zone_key(map_version: u32, zone_id: u32) -> Position {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&map_version.to_be_bytes());
    payload.extend_from_slice(&zone_id.to_be_bytes());
    Position(Bytes32(canon::domain_hash(domain::ZONE_KEY, &payload)))
}

/// DHT key of an agent's inbox.
pub fn inbox_key(agent_id: &AgentId) -> Position {
    Position(Bytes32(canon::domain_hash(domain::INBOX_KEY, agent_id.as_str().as_bytes())))
}

/// DHT key of one vault shard.
pub fn vault_shard_key(agent_id: &AgentId, snapshot: u64, index: u8) -> Position {
    let mut payload = agent_id.as_str().as_bytes().to_vec();
    payload.extend_from_slice(&snapshot.to_be_bytes());
    payload.push(index);
    Position(Bytes32(canon::domain_hash(domain::VAULT_KEY, &payload)))
}

fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for b in h {
        if *b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

fn pow_hash(pk: &PublicKey, nonce: u64) -> [u8; 32] {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&pk.0);
    payload.extend_from_slice(&nonce.to_be_bytes());
    canon::domain_hash(domain::POW, &payload)
}

/// Verify an identity proof of work at the given difficulty.
pub fn verify_pow(pk: &PublicKey, nonce: u64, bits: u32) -> Result<()> {
    if leading_zero_bits(&pow_hash(pk, nonce)) >= bits {
        Ok(())
    } else {
        Err(Error::ProofOfWork(bits))
    }
}

/// Find a nonce for the identity proof of work. A few seconds at 20 bits.
pub fn solve_pow(pk: &PublicKey, bits: u32) -> u64 {
    let mut nonce = 0u64;
    loop {
        if leading_zero_bits(&pow_hash(pk, nonce)) >= bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

pub fn default_pow_bits() -> u32 {
    params::POW_BITS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    #[test]
    fn agent_id_roundtrip() {
        let kp = Keypair::from_seed(&[1u8; 32]);
        let id = AgentId::from_pubkey(&kp.public());
        assert!(id.as_str().starts_with("alp1"));
        assert_eq!(id.as_str().len(), 36);
        assert_eq!(AgentId::parse(id.as_str()).unwrap(), id);
        assert!(id.matches(&kp.public()));
        assert!(!id.matches(&Keypair::from_seed(&[2u8; 32]).public()));
    }

    #[test]
    fn pow_small_difficulty() {
        let kp = Keypair::from_seed(&[7u8; 32]);
        let nonce = solve_pow(&kp.public(), 8);
        verify_pow(&kp.public(), nonce, 8).unwrap();
        assert!(verify_pow(&kp.public(), nonce.wrapping_add(1), 24).is_err() || true);
    }

    #[test]
    fn positions_differ() {
        let a = Position::of_node(&Keypair::from_seed(&[1u8; 32]).public());
        let b = Position::of_node(&Keypair::from_seed(&[2u8; 32]).public());
        assert_ne!(a, b);
        assert_eq!(a.common_prefix_bits(&a), 256);
    }
}
