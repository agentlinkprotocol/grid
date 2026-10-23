//! The vault: an agent's memory, encrypted by its owner, split into 30 Reed-Solomon shards of
//! which any 10 rebuild the whole, each shard signed by the agent and countersigned by the node.

use alp_grid_core::canon;
use alp_grid_core::ids::AgentId;
use alp_grid_core::keys::{self, Bytes32, Bytes64, Keypair, PublicKey};
use alp_grid_core::params::{domain, VAULT_DATA_SHARDS, VAULT_MAX_BYTES, VAULT_SHARDS};
use alp_grid_core::types::{Blob, OperatorCert};
use alp_grid_core::wire::VaultShard;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("snapshot too large: {0} bytes (max {VAULT_MAX_BYTES})")]
    TooLarge(usize),
    #[error("crypto failure")]
    Crypto,
    #[error("not enough shards: have {have}, need {need}")]
    NotEnoughShards { have: usize, need: usize },
    #[error("erasure coding: {0}")]
    Erasure(String),
    #[error(transparent)]
    Core(#[from] alp_grid_core::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Owner-held symmetric key. Losing it loses the memory, for everyone including the owner.
#[derive(Clone)]
pub struct VaultKey(pub [u8; 32]);

impl VaultKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
        VaultKey(k)
    }
}

/// Encrypt a snapshot: nonce(24) || ciphertext. AAD binds it to the agent and snapshot number.
pub fn encrypt(key: &VaultKey, agent_id: &AgentId, snapshot: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() as u64 > VAULT_MAX_BYTES {
        return Err(VaultError::TooLarge(plaintext.len()));
    }
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let aad = aad(agent_id, snapshot);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), chacha20poly1305::aead::Payload { msg: plaintext, aad: &aad })
        .map_err(|_| VaultError::Crypto)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &VaultKey, agent_id: &AgentId, snapshot: u64, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 {
        return Err(VaultError::Crypto);
    }
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let aad = aad(agent_id, snapshot);
    cipher
        .decrypt(XNonce::from_slice(&blob[..24]), chacha20poly1305::aead::Payload { msg: &blob[24..], aad: &aad })
        .map_err(|_| VaultError::Crypto)
}

fn aad(agent_id: &AgentId, snapshot: u64) -> Vec<u8> {
    let mut a = agent_id.as_str().as_bytes().to_vec();
    a.extend_from_slice(&snapshot.to_be_bytes());
    a
}

/// Split `blob` into `VAULT_SHARDS` shards (`VAULT_DATA_SHARDS` data + parity). Each shard is
/// prefixed in shard 0.. by the original length so that reconstruction knows where to cut.
pub fn split(blob: &[u8]) -> Result<Vec<Vec<u8>>> {
    let rs = ReedSolomon::new(VAULT_DATA_SHARDS, VAULT_SHARDS - VAULT_DATA_SHARDS).map_err(|e| VaultError::Erasure(format!("{e:?}")))?;
    let mut framed = (blob.len() as u64).to_be_bytes().to_vec();
    framed.extend_from_slice(blob);
    let shard_len = framed.len().div_ceil(VAULT_DATA_SHARDS);
    let shard_len = shard_len.max(1);
    framed.resize(shard_len * VAULT_DATA_SHARDS, 0);
    let mut shards: Vec<Vec<u8>> = framed.chunks(shard_len).map(|c| c.to_vec()).collect();
    for _ in VAULT_DATA_SHARDS..VAULT_SHARDS {
        shards.push(vec![0u8; shard_len]);
    }
    rs.encode(&mut shards).map_err(|e| VaultError::Erasure(format!("{e:?}")))?;
    Ok(shards)
}

/// Rebuild from any `VAULT_DATA_SHARDS` shards. `shards[i]` is `None` when shard `i` is missing.
pub fn reconstruct(mut shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>> {
    let have = shards.iter().filter(|s| s.is_some()).count();
    if have < VAULT_DATA_SHARDS {
        return Err(VaultError::NotEnoughShards { have, need: VAULT_DATA_SHARDS });
    }
    shards.resize(VAULT_SHARDS, None);
    let rs = ReedSolomon::new(VAULT_DATA_SHARDS, VAULT_SHARDS - VAULT_DATA_SHARDS).map_err(|e| VaultError::Erasure(format!("{e:?}")))?;
    rs.reconstruct_data(&mut shards).map_err(|e| VaultError::Erasure(format!("{e:?}")))?;
    let mut framed = Vec::new();
    for s in shards.iter().take(VAULT_DATA_SHARDS) {
        framed.extend_from_slice(s.as_ref().expect("reconstructed"));
    }
    if framed.len() < 8 {
        return Err(VaultError::Crypto);
    }
    let len = u64::from_be_bytes(framed[..8].try_into().unwrap()) as usize;
    if 8 + len > framed.len() {
        return Err(VaultError::Crypto);
    }
    Ok(framed[8..8 + len].to_vec())
}

#[derive(Serialize)]
struct ShardUnsigned<'a> {
    agent_id: &'a AgentId,
    agent_pubkey: &'a PublicKey,
    snapshot: u64,
    index: u8,
    total: u8,
    data_shards: u8,
    shard_hash: &'a Bytes32,
    expires_at: u64,
}

#[derive(Serialize)]
struct ShardAgentSigned<'a> {
    agent_id: &'a AgentId,
    agent_pubkey: &'a PublicKey,
    snapshot: u64,
    index: u8,
    total: u8,
    data_shards: u8,
    shard_hash: &'a Bytes32,
    expires_at: u64,
    operator_cert: &'a OperatorCert,
    agent_sig: &'a Bytes64,
}

pub fn shard_agent_hash(s: &VaultShard) -> Result<[u8; 32]> {
    Ok(canon::signing_hash(
        domain::VAULT,
        &ShardUnsigned {
            agent_id: &s.agent_id,
            agent_pubkey: &s.agent_pubkey,
            snapshot: s.snapshot,
            index: s.index,
            total: s.total,
            data_shards: s.data_shards,
            shard_hash: &s.shard_hash,
            expires_at: s.expires_at,
        },
    )?)
}

pub fn shard_node_hash(s: &VaultShard) -> Result<[u8; 32]> {
    Ok(canon::signing_hash(
        domain::NODE_SIG,
        &ShardAgentSigned {
            agent_id: &s.agent_id,
            agent_pubkey: &s.agent_pubkey,
            snapshot: s.snapshot,
            index: s.index,
            total: s.total,
            data_shards: s.data_shards,
            shard_hash: &s.shard_hash,
            expires_at: s.expires_at,
            operator_cert: &s.operator_cert,
            agent_sig: &s.agent_sig,
        },
    )?)
}

/// Build the signed shard objects of one snapshot (agent side; node countersigns afterwards).
pub fn make_shards(agent: &Keypair, cert: &OperatorCert, snapshot: u64, encrypted: &[u8], expires_at: u64) -> Result<Vec<VaultShard>> {
    let agent_id = AgentId::from_pubkey(&agent.public());
    let mut out = Vec::with_capacity(VAULT_SHARDS);
    for (i, data) in split(encrypted)?.into_iter().enumerate() {
        let mut s = VaultShard {
            agent_id: agent_id.clone(),
            agent_pubkey: agent.public(),
            snapshot,
            index: i as u8,
            total: VAULT_SHARDS as u8,
            data_shards: VAULT_DATA_SHARDS as u8,
            shard_hash: Bytes32(canon::hash(&data)),
            data: Blob(data),
            expires_at,
            operator_cert: cert.clone(),
            agent_sig: Bytes64::zero(),
            node_sig: Bytes64::zero(),
        };
        s.agent_sig = agent.sign(&shard_agent_hash(&s)?);
        out.push(s);
    }
    Ok(out)
}

pub fn countersign(s: &mut VaultShard, node: &Keypair) -> Result<()> {
    s.node_sig = node.sign(&shard_node_hash(s)?);
    Ok(())
}

/// Guardian-side verification: hashes, signatures, bounds.
pub fn verify_shard(s: &VaultShard, now: u64) -> Result<()> {
    if s.total as usize != VAULT_SHARDS || s.data_shards as usize != VAULT_DATA_SHARDS || s.index >= s.total {
        return Err(alp_grid_core::Error::invalid("shard", "bad geometry").into());
    }
    if Bytes32(canon::hash(&s.data.0)) != s.shard_hash {
        return Err(alp_grid_core::Error::invalid("shard_hash", "does not match data").into());
    }
    if (s.data.0.len() as u64) * VAULT_DATA_SHARDS as u64 > VAULT_MAX_BYTES + 4096 {
        return Err(VaultError::TooLarge(s.data.0.len()));
    }
    if s.expires_at <= now {
        return Err(alp_grid_core::Error::Expired.into());
    }
    if !s.agent_id.matches(&s.agent_pubkey) {
        return Err(alp_grid_core::Error::invalid("agent_id", "does not match key").into());
    }
    s.operator_cert.verify(now)?;
    keys::verify(&s.agent_pubkey, &shard_agent_hash(s)?, &s.agent_sig)?;
    keys::verify(&s.operator_cert.node_pubkey, &shard_node_hash(s)?, &s.node_sig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_split_lose_20_rebuild_decrypt() {
        let agent = Keypair::from_seed(&[1; 32]);
        let node = Keypair::from_seed(&[2; 32]);
        let cert = OperatorCert::self_signed(&node, 0, u64::MAX / 2).unwrap();
        let key = VaultKey::generate();
        let agent_id = AgentId::from_pubkey(&agent.public());
        let memory = b"The agent remembers: user likes astronomy, prefers mornings.".repeat(100);
        let enc = encrypt(&key, &agent_id, 1, &memory).unwrap();
        let mut shards = make_shards(&agent, &cert, 1, &enc, 10_000).unwrap();
        for s in shards.iter_mut() {
            countersign(s, &node).unwrap();
            verify_shard(s, 5).unwrap();
        }
        assert_eq!(shards.len(), 30);
        // lose 20 of 30
        let kept: Vec<Option<Vec<u8>>> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| if i % 3 == 0 { Some(s.data.0.clone()) } else { None })
            .collect();
        let rebuilt = reconstruct(kept).unwrap();
        assert_eq!(rebuilt, enc);
        assert_eq!(decrypt(&key, &agent_id, 1, &rebuilt).unwrap(), memory);
        // 9 shards are not enough
        let few: Vec<Option<Vec<u8>>> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| if i < 9 { Some(s.data.0.clone()) } else { None })
            .collect();
        assert!(reconstruct(few).is_err());
        // wrong snapshot number fails AEAD
        assert!(decrypt(&key, &agent_id, 2, &enc).is_err());
        // tampered shard rejected
        shards[0].data.0[0] ^= 1;
        assert!(verify_shard(&shards[0], 5).is_err());
    }
}
