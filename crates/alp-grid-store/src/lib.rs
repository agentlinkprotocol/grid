//! Durable storage (redb) plus an in-memory vector index for the zones this node guards.
//!
//! Tables:
//! * `cards`:        agent_id -> Card                 (latest version)
//! * `revocations`:  agent_id -> Revocation           (kept until the revoked version would have expired)
//! * `zone_entries`: zone_prefix || entry_key -> StoredEntry (entry + locally computed vector)
//! * `inbox`:        agent_id || message_id -> InboxMessage
//! * `vault`:        agent_id || snapshot || index -> VaultShard
//! * `receipts`:     timestamp || request_hash -> Receipt
//! * `ledger`:       seq (be u64) -> LedgerEntry
//! * `meta`:         small key/values (capacity, ledger root, …)

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use alp_grid_core::canon;
use alp_grid_core::ids::AgentId;
use alp_grid_core::types::*;
use alp_grid_core::wire::{InboxMessage, SearchHit, VaultShard};
use alp_grid_core::{Bytes16, Bytes32, Error as CoreError};
use parking_lot::RwLock;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CARDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("cards");
const REVOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("revocations");
const ZONE_ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("zone_entries");
const INBOX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox");
const VAULT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vault");
const RECEIPTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("receipts");
const LEDGER: TableDefinition<u64, &[u8]> = TableDefinition::new("ledger");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Db(String),
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl From<redb::Error> for StoreError {
    fn from(e: redb::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}
macro_rules! redb_err {
    ($($t:ty),*) => { $(impl From<$t> for StoreError { fn from(e: $t) -> Self { StoreError::Db(e.to_string()) } })* };
}
redb_err!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

pub type Result<T> = std::result::Result<T, StoreError>;

/// What a guardian keeps for one trait in one zone: the entry and the vector it computed itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredEntry {
    pub entry: ZoneEntry,
    pub vector: Vector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZoneRef {
    pub map_version: u32,
    pub zone_id: u32,
}

impl ZoneRef {
    fn prefix(&self) -> [u8; 8] {
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&self.map_version.to_be_bytes());
        p[4..].copy_from_slice(&self.zone_id.to_be_bytes());
        p
    }
    fn key(&self, entry_key: &[u8]) -> Vec<u8> {
        let mut k = self.prefix().to_vec();
        k.extend_from_slice(entry_key);
        k
    }
}

/// In-memory index of one zone. Exact cosine scan; HNSW is planned above `EXACT_SEARCH_MAX_ENTRIES`.
#[derive(Default)]
struct ZoneIndex {
    entries: HashMap<Vec<u8>, StoredEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StoreStats {
    pub cards: u64,
    pub revocations: u64,
    pub zone_entries: u64,
    pub zones: u64,
    pub inbox_messages: u64,
    pub vault_shards: u64,
    pub ledger_entries: u64,
    pub bytes_on_disk: u64,
}

pub struct Store {
    db: Database,
    path: std::path::PathBuf,
    zones: RwLock<HashMap<ZoneRef, ZoneIndex>>,
}

pub type SharedStore = Arc<Store>;

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let db = Database::create(path)?;
        {
            let txn = db.begin_write()?;
            txn.open_table(CARDS)?;
            txn.open_table(REVOCATIONS)?;
            txn.open_table(ZONE_ENTRIES)?;
            txn.open_table(INBOX)?;
            txn.open_table(VAULT)?;
            txn.open_table(RECEIPTS)?;
            txn.open_table(LEDGER)?;
            txn.open_table(META)?;
            txn.commit()?;
        }
        let store = Store {
            db,
            path: path.to_path_buf(),
            zones: RwLock::new(HashMap::new()),
        };
        store.load_zone_index()?;
        Ok(store)
    }

    pub fn open_temp() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("alp-grid-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&dir).map_err(|e| StoreError::Db(e.to_string()))?;
        Self::open(&dir.join("grid.redb"))
    }

    fn load_zone_index(&self) -> Result<()> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(ZONE_ENTRIES)?;
        let mut zones: HashMap<ZoneRef, ZoneIndex> = HashMap::new();
        for item in t.iter()? {
            let (k, v) = item?;
            let k = k.value();
            if k.len() < 8 {
                continue;
            }
            let zr = ZoneRef {
                map_version: u32::from_be_bytes([k[0], k[1], k[2], k[3]]),
                zone_id: u32::from_be_bytes([k[4], k[5], k[6], k[7]]),
            };
            let se: StoredEntry = canon::from_cbor(v.value())?;
            zones.entry(zr).or_default().entries.insert(k[8..].to_vec(), se);
        }
        *self.zones.write() = zones;
        Ok(())
    }

    // ----- cards -----

    pub fn get_card(&self, agent_id: &AgentId) -> Result<Option<Card>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(CARDS)?;
        match t.get(agent_id.as_str().as_bytes())? {
            Some(v) => Ok(Some(canon::from_cbor(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn get_revocation(&self, agent_id: &AgentId) -> Result<Option<Revocation>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(REVOCATIONS)?;
        match t.get(agent_id.as_str().as_bytes())? {
            Some(v) => Ok(Some(canon::from_cbor(v.value())?)),
            None => Ok(None),
        }
    }

    /// Store a card if it is newer than what we hold and not revoked. Returns the previous version.
    pub fn put_card(&self, card: &Card) -> Result<Option<u64>> {
        let prev = self.get_card(&card.agent_id)?;
        if let Some(p) = &prev {
            if card.version <= p.version {
                return Err(CoreError::StaleVersion {
                    got: card.version,
                    known: p.version,
                }
                .into());
            }
        }
        if let Some(r) = self.get_revocation(&card.agent_id)? {
            if let RevocationTarget::Card(v) = r.target {
                if card.version <= v {
                    return Err(CoreError::StaleVersion { got: card.version, known: v }.into());
                }
            }
        }
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(CARDS)?;
            t.insert(card.agent_id.as_str().as_bytes(), canon::to_cbor(card)?.as_slice())?;
        }
        txn.commit()?;
        Ok(prev.map(|p| p.version))
    }

    pub fn put_revocation(&self, r: &Revocation) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(REVOCATIONS)?;
            t.insert(r.agent_id.as_str().as_bytes(), canon::to_cbor(r)?.as_slice())?;
            if let RevocationTarget::Card(v) = r.target {
                let mut cards = txn.open_table(CARDS)?;
                let remove = match cards.get(r.agent_id.as_str().as_bytes())? {
                    Some(c) => canon::from_cbor::<Card>(c.value())?.version <= v,
                    None => false,
                };
                if remove {
                    cards.remove(r.agent_id.as_str().as_bytes())?;
                }
            }
        }
        txn.commit()?;
        match r.target {
            RevocationTarget::Card(v) => self.remove_agent_entries(&r.agent_id, Some(v), None)?,
            RevocationTarget::Ephemeral(id) => self.remove_agent_entries(&r.agent_id, None, Some(id))?,
        };
        Ok(())
    }

    pub fn list_cards(&self, limit: usize) -> Result<Vec<Card>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(CARDS)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (_, v) = item?;
            out.push(canon::from_cbor(v.value())?);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    // ----- zone entries -----

    pub fn put_zone_entry(&self, zone: ZoneRef, entry: ZoneEntry, vector: Vector) -> Result<()> {
        let se = StoredEntry { entry, vector };
        let ekey = se.entry.key();
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(ZONE_ENTRIES)?;
            t.insert(zone.key(&ekey).as_slice(), canon::to_cbor(&se)?.as_slice())?;
        }
        txn.commit()?;
        self.zones.write().entry(zone).or_default().entries.insert(ekey, se);
        Ok(())
    }

    /// Remove an agent's permanent entries with card_version <= `below_version`, and/or one ephemeral.
    pub fn remove_agent_entries(&self, agent_id: &AgentId, below_version: Option<u64>, ephemeral: Option<Bytes16>) -> Result<usize> {
        let mut to_remove: Vec<(ZoneRef, Vec<u8>)> = Vec::new();
        {
            let zones = self.zones.read();
            for (zr, idx) in zones.iter() {
                for (k, se) in idx.entries.iter() {
                    if &se.entry.agent_id != agent_id {
                        continue;
                    }
                    let hit = match (&se.entry.kind, below_version, ephemeral) {
                        (EntryKind::Permanent, Some(v), _) if se.entry.card_version <= v => true,
                        (EntryKind::Ephemeral { ephemeral_id, .. }, _, Some(id)) if *ephemeral_id == id => true,
                        (EntryKind::Ephemeral { .. }, Some(v), None) if se.entry.card_version <= v => false,
                        _ => false,
                    };
                    if hit {
                        to_remove.push((*zr, k.clone()));
                    }
                }
            }
        }
        self.remove_entries(&to_remove)?;
        Ok(to_remove.len())
    }

    /// Remove specific entries (by entry key) from one zone only.
    pub fn remove_zone_entries(&self, zone: ZoneRef, keys: &[Vec<u8>]) -> Result<()> {
        let items: Vec<(ZoneRef, Vec<u8>)> = keys.iter().map(|k| (zone, k.clone())).collect();
        self.remove_entries(&items)
    }

    fn remove_entries(&self, items: &[(ZoneRef, Vec<u8>)]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(ZONE_ENTRIES)?;
            for (zr, k) in items {
                t.remove(zr.key(k).as_slice())?;
            }
        }
        txn.commit()?;
        let mut zones = self.zones.write();
        for (zr, k) in items {
            if let Some(idx) = zones.get_mut(zr) {
                idx.entries.remove(k);
                if idx.entries.is_empty() {
                    zones.remove(zr);
                }
            }
        }
        Ok(())
    }

    /// Entries of an agent currently held in a zone (used to drop traits that disappeared in a new version).
    pub fn agent_entries_in_zone(&self, zone: ZoneRef, agent_id: &AgentId) -> Vec<ZoneEntry> {
        let zones = self.zones.read();
        zones
            .get(&zone)
            .map(|idx| {
                idx.entries
                    .values()
                    .filter(|se| &se.entry.agent_id == agent_id)
                    .map(|se| se.entry.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn zone_entry_hashes(&self, zone: ZoneRef) -> Vec<Bytes32> {
        let zones = self.zones.read();
        zones
            .get(&zone)
            .map(|idx| {
                idx.entries
                    .values()
                    .filter_map(|se| canon::to_cbor(&se.entry).ok())
                    .map(|b| Bytes32(canon::hash(&b)))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn zone_entries(&self, zone: ZoneRef) -> Vec<StoredEntry> {
        let zones = self.zones.read();
        zones.get(&zone).map(|idx| idx.entries.values().cloned().collect()).unwrap_or_default()
    }

    pub fn zones_held(&self) -> Vec<(ZoneRef, usize)> {
        let zones = self.zones.read();
        let mut v: Vec<(ZoneRef, usize)> = zones.iter().map(|(z, i)| (*z, i.entries.len())).collect();
        v.sort();
        v
    }

    /// Exact search in one zone: filters first, then cosine, then top-k.
    /// Ephemerals count only when `at` falls inside their window; permanent entries always count.
    pub fn search(&self, zone: ZoneRef, vector: &Vector, filters: &Filters, at: Option<u64>, k: usize, now: u64) -> Vec<SearchHit> {
        let zones = self.zones.read();
        let Some(idx) = zones.get(&zone) else { return vec![] };
        let mut hits: Vec<SearchHit> = idx
            .entries
            .values()
            .filter(|se| se.entry.expires_at > now)
            .filter(|se| match &se.entry.kind {
                EntryKind::Permanent => true,
                EntryKind::Ephemeral { valid_from, valid_until, .. } => match at {
                    Some(t) => t >= *valid_from && t <= *valid_until,
                    None => false,
                },
            })
            .filter(|se| se.entry.filters.matches(filters))
            .map(|se| SearchHit {
                agent_id: se.entry.agent_id.clone(),
                card_version: se.entry.card_version,
                trait_index: se.entry.trait_index,
                text: se.entry.text.clone(),
                score: se.vector.dot(vector),
                last_seen: se.entry.last_seen,
                kind: se.entry.kind.clone(),
            })
            .collect();
        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(k);
        hits
    }

    /// Drop expired cards, entries, inbox messages and shards. Returns how many items went.
    pub fn expire(&self, now: u64) -> Result<usize> {
        let mut n = 0;
        let mut dead: Vec<(ZoneRef, Vec<u8>)> = Vec::new();
        {
            let zones = self.zones.read();
            for (zr, idx) in zones.iter() {
                for (k, se) in idx.entries.iter() {
                    if se.entry.expires_at <= now {
                        dead.push((*zr, k.clone()));
                    }
                }
            }
        }
        n += dead.len();
        self.remove_entries(&dead)?;

        let txn = self.db.begin_write()?;
        {
            let mut cards = txn.open_table(CARDS)?;
            let mut gone = Vec::new();
            for item in cards.iter()? {
                let (k, v) = item?;
                let c: Card = canon::from_cbor(v.value())?;
                if c.expires_at <= now {
                    gone.push(k.value().to_vec());
                }
            }
            for k in gone {
                cards.remove(k.as_slice())?;
                n += 1;
            }
            let mut inbox = txn.open_table(INBOX)?;
            let mut gone = Vec::new();
            for item in inbox.iter()? {
                let (k, v) = item?;
                let m: InboxMessage = canon::from_cbor(v.value())?;
                if m.expires_at <= now {
                    gone.push(k.value().to_vec());
                }
            }
            for k in gone {
                inbox.remove(k.as_slice())?;
                n += 1;
            }
            let mut vault = txn.open_table(VAULT)?;
            let mut gone = Vec::new();
            for item in vault.iter()? {
                let (k, v) = item?;
                let s: VaultShard = canon::from_cbor(v.value())?;
                if s.expires_at <= now {
                    gone.push(k.value().to_vec());
                }
            }
            for k in gone {
                vault.remove(k.as_slice())?;
                n += 1;
            }
        }
        txn.commit()?;
        Ok(n)
    }

    // ----- inbox -----

    fn inbox_key(to: &AgentId, id: &Bytes16) -> Vec<u8> {
        let mut k = to.as_str().as_bytes().to_vec();
        k.push(0);
        k.extend_from_slice(&id.0);
        k
    }

    pub fn inbox_put(&self, m: &InboxMessage) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(INBOX)?;
            t.insert(Self::inbox_key(&m.to, &m.message_id).as_slice(), canon::to_cbor(m)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn inbox_list(&self, to: &AgentId) -> Result<Vec<InboxMessage>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(INBOX)?;
        let mut prefix = to.as_str().as_bytes().to_vec();
        prefix.push(0);
        let mut end = prefix.clone();
        end.push(0xff);
        let mut out = Vec::new();
        for item in t.range(prefix.as_slice()..end.as_slice())? {
            let (_, v) = item?;
            out.push(canon::from_cbor(v.value())?);
        }
        Ok(out)
    }

    pub fn inbox_remove(&self, to: &AgentId, ids: &[Bytes16]) -> Result<usize> {
        let txn = self.db.begin_write()?;
        let mut n = 0;
        {
            let mut t = txn.open_table(INBOX)?;
            for id in ids {
                if t.remove(Self::inbox_key(to, id).as_slice())?.is_some() {
                    n += 1;
                }
            }
        }
        txn.commit()?;
        Ok(n)
    }

    // ----- vault -----

    fn vault_key(agent: &AgentId, snapshot: u64, index: u8) -> Vec<u8> {
        let mut k = agent.as_str().as_bytes().to_vec();
        k.push(0);
        k.extend_from_slice(&snapshot.to_be_bytes());
        k.push(index);
        k
    }

    pub fn vault_put(&self, s: &VaultShard) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(VAULT)?;
            t.insert(Self::vault_key(&s.agent_id, s.snapshot, s.index).as_slice(), canon::to_cbor(s)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn vault_get(&self, agent: &AgentId, snapshot: u64, index: u8) -> Result<Option<VaultShard>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(VAULT)?;
        match t.get(Self::vault_key(agent, snapshot, index).as_slice())? {
            Some(v) => Ok(Some(canon::from_cbor(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn vault_bytes_for(&self, agent: &AgentId) -> Result<u64> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(VAULT)?;
        let mut prefix = agent.as_str().as_bytes().to_vec();
        prefix.push(0);
        let mut end = prefix.clone();
        end.push(0xff);
        let mut n = 0u64;
        for item in t.range(prefix.as_slice()..end.as_slice())? {
            let (_, v) = item?;
            n += v.value().len() as u64;
        }
        Ok(n)
    }

    // ----- receipts -----

    pub fn receipt_put(&self, r: &Receipt) -> Result<()> {
        let mut k = r.timestamp.to_be_bytes().to_vec();
        k.extend_from_slice(&r.request_hash.0);
        k.extend_from_slice(&r.node_pubkey.0[..8]);
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(RECEIPTS)?;
            t.insert(k.as_slice(), canon::to_cbor(r)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn receipts_since(&self, since: u64, limit: usize) -> Result<Vec<Receipt>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(RECEIPTS)?;
        let start = since.to_be_bytes().to_vec();
        let mut out = Vec::new();
        for item in t.range(start.as_slice()..)? {
            let (_, v) = item?;
            out.push(canon::from_cbor(v.value())?);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn receipts_prune(&self, before: u64) -> Result<usize> {
        let txn = self.db.begin_write()?;
        let mut n = 0;
        {
            let mut t = txn.open_table(RECEIPTS)?;
            let end = before.to_be_bytes().to_vec();
            let gone: Vec<Vec<u8>> = t.range(..end.as_slice())?.filter_map(|i| i.ok()).map(|(k, _)| k.value().to_vec()).collect();
            for k in gone {
                t.remove(k.as_slice())?;
                n += 1;
            }
        }
        txn.commit()?;
        Ok(n)
    }

    // ----- ledger -----

    pub fn ledger_len(&self) -> Result<u64> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(LEDGER)?;
        Ok(t.len()?)
    }

    pub fn ledger_last(&self) -> Result<Option<LedgerEntry>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(LEDGER)?;
        let last = t.last()?;
        let out = match last {
            Some((_, v)) => Some(canon::from_cbor(v.value())?),
            None => None,
        };
        Ok(out)
    }

    pub fn ledger_append(&self, e: &LedgerEntry) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(LEDGER)?;
            t.insert(e.seq, canon::to_cbor(e)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn ledger_range(&self, from: u64, limit: usize) -> Result<Vec<LedgerEntry>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(LEDGER)?;
        let mut out = Vec::new();
        for item in t.range(from..)? {
            let (_, v) = item?;
            out.push(canon::from_cbor(v.value())?);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    // ----- meta -----

    pub fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        Ok(t.get(key)?.map(|v| v.value().to_vec()))
    }

    pub fn meta_set(&self, key: &str, value: &[u8]) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(META)?;
            t.insert(key, value)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let txn = self.db.begin_read()?;
        let zones = self.zones.read();
        Ok(StoreStats {
            cards: txn.open_table(CARDS)?.len()?,
            revocations: txn.open_table(REVOCATIONS)?.len()?,
            zone_entries: zones.values().map(|z| z.entries.len() as u64).sum(),
            zones: zones.len() as u64,
            inbox_messages: txn.open_table(INBOX)?.len()?,
            vault_shards: txn.open_table(VAULT)?.len()?,
            ledger_entries: txn.open_table(LEDGER)?.len()?,
            bytes_on_disk: std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0),
        })
    }
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    nanos ^ (COUNTER.fetch_add(1, Ordering::Relaxed) << 48)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alp_grid_core::keys::{Bytes64, Keypair};
    use alp_grid_core::params::{CARD_MAX_TTL, MODEL_V1};
    use alp_grid_core::time::DAY;

    fn card(agent: &Keypair, node: &Keypair, version: u64, traits: &[&str], now: u64) -> Card {
        let cert = OperatorCert::self_signed(node, now - DAY, now + 365 * DAY).unwrap();
        let mut c = Card {
            agent_id: AgentId::from_pubkey(&agent.public()),
            agent_pubkey: agent.public(),
            version,
            endpoints: vec![],
            traits: traits.iter().map(|s| s.to_string()).collect(),
            filters: Filters::default(),
            model: MODEL_V1.into(),
            map_version: 1,
            issued_at: now,
            last_seen: now,
            expires_at: now + CARD_MAX_TTL,
            operator_cert: cert,
            agent_sig: Bytes64::zero(),
            node_sig: Bytes64::zero(),
        };
        c.sign_agent(agent).unwrap();
        c.countersign(node, now).unwrap();
        c
    }

    #[test]
    fn cards_versions_and_revocation() {
        let s = Store::open_temp().unwrap();
        let now = 1_800_000_000;
        let agent = Keypair::from_seed(&[1; 32]);
        let node = Keypair::from_seed(&[2; 32]);
        let c1 = card(&agent, &node, 1, &["Developer"], now);
        let c2 = card(&agent, &node, 2, &["Developer", "Astronomer"], now);
        assert_eq!(s.put_card(&c1).unwrap(), None);
        assert_eq!(s.put_card(&c2).unwrap(), Some(1));
        assert!(s.put_card(&c1).is_err());
        assert_eq!(s.get_card(&c1.agent_id).unwrap().unwrap().version, 2);
        let r = Revocation::new_signed(&agent, c1.agent_id.clone(), RevocationTarget::Card(2), RevokedBy::Agent, now).unwrap();
        s.put_revocation(&r).unwrap();
        assert!(s.get_card(&c1.agent_id).unwrap().is_none());
        assert!(s.put_card(&c2).is_err());
        let c3 = card(&agent, &node, 3, &["Developer"], now);
        s.put_card(&c3).unwrap();
    }

    #[test]
    fn zone_search_and_expiry() {
        let s = Store::open_temp().unwrap();
        let now = 1_800_000_000;
        let z = ZoneRef { map_version: 1, zone_id: 7 };
        let agent = Keypair::from_seed(&[1; 32]);
        let node = Keypair::from_seed(&[2; 32]);
        let c = card(&agent, &node, 1, &["Developer", "Astronomer"], now);
        let mut v0 = Vector(vec![0.0; 384]);
        v0.0[0] = 1.0;
        let mut v1 = Vector(vec![0.0; 384]);
        v1.0[1] = 1.0;
        s.put_zone_entry(z, ZoneEntry::from_card(&c, 0).unwrap(), v0.clone()).unwrap();
        s.put_zone_entry(z, ZoneEntry::from_card(&c, 1).unwrap(), v1.clone()).unwrap();
        let hits = s.search(z, &v0, &Filters::default(), None, 10, now);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].trait_index, 0);
        assert!(hits[0].score > hits[1].score);
        // ephemeral only visible with `at`
        let mut e = ZoneEntry::from_card(&c, 0).unwrap();
        e.kind = EntryKind::Ephemeral {
            ephemeral_id: Bytes16([9; 16]),
            valid_from: now + 100,
            valid_until: now + 200,
        };
        e.expires_at = now + 200;
        s.put_zone_entry(z, e, v0.clone()).unwrap();
        assert_eq!(s.search(z, &v0, &Filters::default(), None, 10, now).len(), 2);
        assert_eq!(s.search(z, &v0, &Filters::default(), Some(now + 150), 10, now).len(), 3);
        assert_eq!(s.search(z, &v0, &Filters::default(), Some(now + 300), 10, now).len(), 2);
        // expiry removes the ephemeral
        assert_eq!(s.expire(now + 201).unwrap(), 1);
        assert_eq!(s.zones_held(), vec![(z, 2)]);
        // removing by version
        assert_eq!(s.remove_agent_entries(&c.agent_id, Some(1), None).unwrap(), 2);
        assert!(s.zones_held().is_empty());
    }

    #[test]
    fn index_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("alp-grid-reopen-{}", rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("grid.redb");
        let now = 1_800_000_000;
        let agent = Keypair::from_seed(&[1; 32]);
        let node = Keypair::from_seed(&[2; 32]);
        let c = card(&agent, &node, 1, &["Developer"], now);
        let z = ZoneRef { map_version: 1, zone_id: 3 };
        {
            let s = Store::open(&path).unwrap();
            s.put_zone_entry(z, ZoneEntry::from_card(&c, 0).unwrap(), Vector(vec![1.0; 384])).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.zones_held(), vec![(z, 1)]);
    }

    #[test]
    fn ledger_and_inbox() {
        let s = Store::open_temp().unwrap();
        let node = Keypair::from_seed(&[2; 32]);
        let e = LedgerEntry {
            seq: 0,
            prev_hash: Bytes32::zero(),
            timestamp: 1,
            event: LedgerEvent::OperatorCert(OperatorCert::self_signed(&node, 0, 10).unwrap()),
            witnesses: vec![],
        };
        s.ledger_append(&e).unwrap();
        assert_eq!(s.ledger_len().unwrap(), 1);
        assert_eq!(s.ledger_last().unwrap().unwrap(), e);
        let to = AgentId::from_pubkey(&node.public());
        let m = InboxMessage {
            to: to.clone(),
            from_pubkey: node.public(),
            message_id: Bytes16([1; 16]),
            ciphertext: Blob(vec![1, 2, 3]),
            deposited_at: 1,
            expires_at: 100,
            operator_cert: OperatorCert::self_signed(&node, 0, 10).unwrap(),
            node_sig: Bytes64::zero(),
        };
        s.inbox_put(&m).unwrap();
        assert_eq!(s.inbox_list(&to).unwrap().len(), 1);
        assert_eq!(s.inbox_remove(&to, &[Bytes16([1; 16])]).unwrap(), 1);
        assert!(s.inbox_list(&to).unwrap().is_empty());
    }
}
