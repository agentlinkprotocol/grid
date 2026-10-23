//! The transparency ledger: a hash chain of public facts with an RFC 6962 Merkle tree hash,
//! stored in redb, witnessed by this node, roots gossiped to peers.

use std::sync::Arc;

use alp_grid_core::canon;
use alp_grid_core::keys::{Bytes32, Keypair};
use alp_grid_core::types::{LedgerEntry, LedgerEvent};
use alp_grid_core::{Error, Result};
use alp_grid_store::Store;
use parking_lot::Mutex;

pub struct Ledger {
    store: Arc<Store>,
    node: Keypair,
    cache: Mutex<Vec<Bytes32>>, // entry hashes in order
}

/// RFC 6962 Merkle tree hash over leaf hashes. Leaves are already hashes, so MTH({d}) = blake3(0x00 || d)
/// and interior nodes are blake3(0x01 || left || right).
pub fn merkle_root(leaves: &[Bytes32]) -> Bytes32 {
    fn mth(l: &[Bytes32]) -> [u8; 32] {
        match l.len() {
            0 => canon::hash(&[]),
            1 => {
                let mut p = vec![0u8];
                p.extend_from_slice(&l[0].0);
                canon::hash(&p)
            }
            n => {
                let k = n.next_power_of_two() / 2;
                let (a, b) = l.split_at(k);
                let mut p = vec![1u8];
                p.extend_from_slice(&mth(a));
                p.extend_from_slice(&mth(b));
                canon::hash(&p)
            }
        }
    }
    Bytes32(mth(leaves))
}

impl Ledger {
    pub fn open(store: Arc<Store>, node: Keypair) -> Result<Self> {
        let mut hashes = Vec::new();
        let mut from = 0;
        loop {
            let batch = store.ledger_range(from, 1000).map_err(|e| Error::Other(e.to_string()))?;
            if batch.is_empty() {
                break;
            }
            for e in &batch {
                hashes.push(e.hash()?);
            }
            from = batch.last().unwrap().seq + 1;
        }
        Ok(Ledger {
            store,
            node,
            cache: Mutex::new(hashes),
        })
    }

    pub fn len(&self) -> u64 {
        self.cache.lock().len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn root(&self) -> Bytes32 {
        merkle_root(&self.cache.lock())
    }

    /// Append a fact witnessed by this node.
    pub fn append(&self, event: LedgerEvent, now: u64) -> Result<LedgerEntry> {
        let mut cache = self.cache.lock();
        let seq = cache.len() as u64;
        let prev_hash = cache.last().copied().unwrap_or_default();
        let mut e = LedgerEntry {
            seq,
            prev_hash,
            timestamp: now,
            event,
            witnesses: vec![],
        };
        e.witness(&self.node)?;
        self.store.ledger_append(&e).map_err(|e| Error::Other(e.to_string()))?;
        cache.push(e.hash()?);
        Ok(e)
    }

    /// Import entries received from a peer that extend our chain. Rejects anything that does not chain.
    pub fn import(&self, entries: &[LedgerEntry]) -> Result<usize> {
        let mut cache = self.cache.lock();
        let mut n = 0;
        for e in entries {
            let expected_seq = cache.len() as u64;
            if e.seq < expected_seq {
                continue; // already have it
            }
            if e.seq != expected_seq {
                return Err(Error::invalid("seq", format!("gap: expected {expected_seq}, got {}", e.seq)));
            }
            let expected_prev = cache.last().copied().unwrap_or_default();
            if e.prev_hash != expected_prev {
                return Err(Error::invalid("prev_hash", "does not chain"));
            }
            if e.verify_witnesses()? == 0 {
                return Err(Error::Signature("ledger entry has no valid witness"));
            }
            self.store.ledger_append(e).map_err(|e| Error::Other(e.to_string()))?;
            cache.push(e.hash()?);
            n += 1;
        }
        Ok(n)
    }

    pub fn range(&self, from: u64, limit: usize) -> Result<Vec<LedgerEntry>> {
        self.store.ledger_range(from, limit).map_err(|e| Error::Other(e.to_string()))
    }

    /// Verify a full chain received from elsewhere (audit).
    pub fn verify_chain(entries: &[LedgerEntry]) -> Result<Bytes32> {
        let mut prev = Bytes32::zero();
        let mut hashes = Vec::with_capacity(entries.len());
        for (i, e) in entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return Err(Error::invalid("chain", format!("broken at {i}")));
            }
            e.verify_witnesses()?;
            prev = e.hash()?;
            hashes.push(prev);
        }
        Ok(merkle_root(&hashes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alp_grid_core::types::OperatorCert;

    #[test]
    fn chain_and_root() {
        let store = Arc::new(Store::open_temp().unwrap());
        let node = Keypair::from_seed(&[2; 32]);
        let ledger = Ledger::open(store.clone(), node.clone()).unwrap();
        let r0 = ledger.root();
        for i in 0..5u64 {
            ledger
                .append(LedgerEvent::OperatorCert(OperatorCert::self_signed(&node, i, i + 100).unwrap()), 1000 + i)
                .unwrap();
        }
        assert_eq!(ledger.len(), 5);
        assert_ne!(ledger.root(), r0);
        let all = ledger.range(0, 100).unwrap();
        assert_eq!(Ledger::verify_chain(&all).unwrap(), ledger.root());

        // a second node imports the chain and ends with the same root
        let store2 = Arc::new(Store::open_temp().unwrap());
        let l2 = Ledger::open(store2, Keypair::from_seed(&[3; 32])).unwrap();
        assert_eq!(l2.import(&all).unwrap(), 5);
        assert_eq!(l2.root(), ledger.root());
        // tampering breaks the chain
        let mut bad = all.clone();
        bad[2].timestamp += 1;
        assert!(Ledger::verify_chain(&bad).is_err());
    }
}
