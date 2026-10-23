//! The engine: everything a node does, independent of how bytes travel.
//!
//! * As a **guardian** ([`Engine::handle`]): validates what it receives, recomputes vectors,
//!   stores, answers searches, and signs a receipt for every answer.
//! * As a **publisher / searcher** (`publish_*`, `search`, …): countersigns what local agents
//!   hand it, finds guardians through the [`Transport`], fans out, verifies receipts.
//! * As a **controller** ([`Engine::run_challenge_round`]): challenges the nodes it was drawn for
//!   and records failures in the ledger.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alp_grid_balance::Capacity;
use alp_grid_core::canon;
use alp_grid_core::ids::{self, AgentId, Position};
use alp_grid_core::keys::{Bytes16, Bytes32, Keypair, PublicKey};
use alp_grid_core::params::*;
use alp_grid_core::transport::{InboundHandler, NetPrefix, NodeRef, Transport, TransportError};
use alp_grid_core::types::*;
use alp_grid_core::validate;
use alp_grid_core::wire::*;
use alp_grid_core::{Error as CoreError, Result as CoreResult};
use alp_grid_embed::Embedder;
use alp_grid_map::Map;
use alp_grid_store::{Store, ZoneRef};
use alp_grid_trust::{challenge, quota, Contribution, Ledger, Reputation, ServiceBook};
use futures::future::join_all;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use utoipa::ToSchema;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Identity {
    pub node: Keypair,
    pub operator: Keypair,
    pub cert: OperatorCert,
    pub pow_nonce: u64,
    pub prefix: NetPrefix,
}

impl Identity {
    /// A node that is its own operator, with a fresh proof of work.
    pub fn self_operated(node: Keypair, now: u64, pow_bits: u32) -> CoreResult<Self> {
        let cert = OperatorCert::self_signed(&node, now.saturating_sub(60), now + 365 * alp_grid_core::time::DAY)?;
        let pow_nonce = ids::solve_pow(&node.public(), pow_bits);
        Ok(Identity {
            operator: node.clone(),
            node,
            cert,
            pow_nonce,
            prefix: NetPrefix::default(),
        })
    }
    pub fn node_ref(&self) -> NodeRef {
        NodeRef {
            pubkey: self.node.public(),
            operator: self.operator.public(),
            prefix: self.prefix.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Metrics {
    pub inbound: [AtomicU64; 8],
    pub rejected: AtomicU64,
    pub searches_made: AtomicU64,
    pub publishes_made: AtomicU64,
    pub receipts_ok: AtomicU64,
    pub receipts_bad: AtomicU64,
    pub challenges_sent: AtomicU64,
    pub challenges_failed: AtomicU64,
    /// (minute, searches served) ring, last 24 h
    pub served_per_minute: Mutex<Vec<(u64, u64)>>,
}

impl Metrics {
    fn bump(&self, kind: ReceiptKind) {
        self.inbound[kind as usize].fetch_add(1, Ordering::Relaxed);
    }
    fn served_search(&self, now: u64) {
        let minute = now / 60;
        let mut v = self.served_per_minute.lock();
        match v.last_mut() {
            Some((m, c)) if *m == minute => *c += 1,
            _ => v.push((minute, 1)),
        }
        if v.len() > 1440 {
            let drop = v.len() - 1440;
            v.drain(..drop);
        }
    }
    pub fn snapshot(&self) -> MetricsSnapshot {
        let kinds = ["store", "search", "card", "challenge", "sync", "inbox", "vault", "ledger"];
        MetricsSnapshot {
            inbound: kinds
                .iter()
                .enumerate()
                .map(|(i, k)| (k.to_string(), self.inbound[i].load(Ordering::Relaxed)))
                .collect(),
            rejected: self.rejected.load(Ordering::Relaxed),
            searches_made: self.searches_made.load(Ordering::Relaxed),
            publishes_made: self.publishes_made.load(Ordering::Relaxed),
            receipts_ok: self.receipts_ok.load(Ordering::Relaxed),
            receipts_bad: self.receipts_bad.load(Ordering::Relaxed),
            challenges_sent: self.challenges_sent.load(Ordering::Relaxed),
            challenges_failed: self.challenges_failed.load(Ordering::Relaxed),
            served_per_minute: self.served_per_minute.lock().iter().rev().take(60).rev().cloned().collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct MetricsSnapshot {
    pub inbound: HashMap<String, u64>,
    pub rejected: u64,
    pub searches_made: u64,
    pub publishes_made: u64,
    pub receipts_ok: u64,
    pub receipts_bad: u64,
    pub challenges_sent: u64,
    pub challenges_failed: u64,
    pub served_per_minute: Vec<(u64, u64)>,
}

// ---------------------------------------------------------------------------
// Trust state
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TrustState {
    pub book: ServiceBook,
    pub rep: Reputation,
    /// Agents we hold cards for, per operator (quota accounting from our own view).
    pub operator_agents: HashMap<PublicKey, HashSet<AgentId>>,
    pub operator_first_seen: HashMap<PublicKey, u64>,
    pub operator_nodes: HashMap<PublicKey, HashSet<PublicKey>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SyncTarget {
    Zone(ZoneRef),
    Card,
}

// ---------------------------------------------------------------------------
// Public DTOs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ZoneReport {
    pub zone_id: u32,
    pub copies: usize,
    pub targets: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct PublishReport {
    pub agent_id: Option<AgentId>,
    pub version: Option<u64>,
    /// Guardians that accepted the full card (0 for ephemerals and revocations).
    pub card_copies: usize,
    pub card_targets: usize,
    pub zones: Vec<ZoneReport>,
    pub rejections: Vec<String>,
    pub took_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct SearchQuery {
    /// Natural-language query; embedded by the node. Either `text` or `vector`.
    pub text: Option<String>,
    pub vector: Option<Vector>,
    #[serde(default)]
    pub filters: Filters,
    /// Target date (unix seconds). Enables ephemerals and disables the cache.
    pub at: Option<u64>,
    /// Max agents returned (default 10, max 100).
    pub k: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AgentResult {
    pub agent_id: AgentId,
    pub card_version: u64,
    pub score: f32,
    pub last_seen: u64,
    pub best_trait: String,
    pub matches: Vec<SearchHit>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct SearchResult {
    pub results: Vec<AgentResult>,
    pub zones_queried: Vec<u32>,
    pub guardians_answered: usize,
    pub cached: bool,
    pub took_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct DepositReport {
    pub message_id: Bytes16,
    pub copies: usize,
    pub targets: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct VaultPutReport {
    pub snapshot: u64,
    pub shards_stored: usize,
    pub shards_total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct VaultGetReport {
    pub snapshot: u64,
    pub shards_found: usize,
    /// The reconstructed encrypted snapshot (hex). Only the owner can decrypt it.
    pub encrypted: Option<Blob>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ChallengeRoundReport {
    pub round: u64,
    pub challenged: usize,
    pub failed: usize,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct Engine {
    pub identity: Identity,
    pub store: Arc<Store>,
    pub map: Arc<Map>,
    pub embedder: Arc<dyn Embedder>,
    pub ledger: Ledger,
    pub trust: RwLock<TrustState>,
    pub capacity: RwLock<Capacity>,
    pub metrics: Metrics,
    pub enforce_quota: bool,
    pub started_at: u64,
    /// Zones probed per search (network parameter NPROBE; raised by the simulator on small maps).
    pub nprobe: std::sync::atomic::AtomicUsize,
    transport: RwLock<Option<Arc<dyn Transport>>>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    search_cache: Mutex<HashMap<Bytes32, (u64, SearchResult)>>,
    sync_targets: RwLock<HashMap<Position, SyncTarget>>,
    own_agents: RwLock<HashSet<AgentId>>,
}

const OWN_AGENTS_META: &str = "own_agents";

impl Engine {
    pub fn new(identity: Identity, store: Arc<Store>, map: Arc<Map>, embedder: Arc<dyn Embedder>, capacity: Capacity, enforce_quota: bool) -> CoreResult<Self> {
        Self::with_clock(identity, store, map, embedder, capacity, enforce_quota, Box::new(alp_grid_core::time::now))
    }

    pub fn with_clock(
        identity: Identity,
        store: Arc<Store>,
        map: Arc<Map>,
        embedder: Arc<dyn Embedder>,
        capacity: Capacity,
        enforce_quota: bool,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> CoreResult<Self> {
        let ledger = Ledger::open(store.clone(), identity.node.clone())?;
        let now = clock();
        let own: HashSet<AgentId> = store
            .meta_get(OWN_AGENTS_META)
            .ok()
            .flatten()
            .and_then(|b| canon::from_cbor::<Vec<AgentId>>(&b).ok())
            .map(|v| v.into_iter().collect())
            .unwrap_or_default();
        let e = Engine {
            identity,
            store,
            map,
            embedder,
            ledger,
            trust: RwLock::new(TrustState::default()),
            capacity: RwLock::new(capacity),
            metrics: Metrics::default(),
            enforce_quota,
            started_at: now,
            nprobe: std::sync::atomic::AtomicUsize::new(NPROBE),
            transport: RwLock::new(None),
            clock,
            search_cache: Mutex::new(HashMap::new()),
            sync_targets: RwLock::new(HashMap::new()),
            own_agents: RwLock::new(own),
        };
        if e.ledger.is_empty() {
            e.ledger.append(LedgerEvent::OperatorCert(e.identity.cert.clone()), now)?;
        }
        // rebuild sync targets from what we hold
        {
            let mut st = e.sync_targets.write();
            for (zr, _) in e.store.zones_held() {
                st.insert(ids::zone_key(zr.map_version, zr.zone_id), SyncTarget::Zone(zr));
            }
            for c in e.store.list_cards(usize::MAX).unwrap_or_default() {
                st.insert(ids::card_key(&c.agent_id), SyncTarget::Card);
            }
        }
        Ok(e)
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    pub fn set_transport(&self, t: Arc<dyn Transport>) {
        *self.transport.write() = Some(t);
    }

    pub fn me(&self) -> NodeRef {
        self.identity.node_ref()
    }

    pub fn model(&self) -> &str {
        self.embedder.model_id()
    }

    /// Nodes currently known through the transport (empty offline).
    pub fn known_nodes(&self) -> Vec<NodeRef> {
        self.transport.read().as_ref().map(|t| t.known()).unwrap_or_default()
    }

    pub fn own_agents(&self) -> Vec<AgentId> {
        self.own_agents.read().iter().cloned().collect()
    }

    fn remember_own(&self, id: &AgentId) {
        let mut own = self.own_agents.write();
        if own.insert(id.clone()) {
            let v: Vec<AgentId> = own.iter().cloned().collect();
            if let Ok(b) = canon::to_cbor(&v) {
                let _ = self.store.meta_set(OWN_AGENTS_META, &b);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Guardian side
    // -----------------------------------------------------------------------

    fn receipt(&self, request_hash: Bytes32, kind: ReceiptKind, outcome: Outcome, response_hash: Bytes32) -> Receipt {
        if !matches!(outcome, Outcome::Ok) {
            self.metrics.rejected.fetch_add(1, Ordering::Relaxed);
        }
        Receipt::issue(&self.identity.node, request_hash, kind, self.now(), outcome, response_hash).expect("receipt encoding")
    }

    fn outcome(r: CoreResult<()>) -> Outcome {
        match r {
            Ok(()) => Outcome::Ok,
            Err(e) => Outcome::Rejected(e.to_string()),
        }
    }

    /// Handle one inbound request as a guardian. Pure CPU; safe to call from anywhere.
    pub fn handle(&self, from: Option<NodeRef>, req: AtlasRequest) -> AtlasResponse {
        let now = self.now();
        let request_hash = Bytes32(canon::hash(&canon::to_cbor(&req).unwrap_or_default()));
        if let Some(f) = &from {
            let mut t = self.trust.write();
            t.operator_nodes.entry(f.operator).or_default().insert(f.pubkey);
            t.operator_first_seen.entry(f.operator).or_insert(now);
        }
        match req {
            AtlasRequest::Store(s) => {
                self.metrics.bump(ReceiptKind::Store);
                let outcome = Self::outcome(self.handle_store(s, now));
                AtlasResponse::Store(StoreResponse {
                    receipt: self.receipt(request_hash, ReceiptKind::Store, outcome, Bytes32::zero()),
                })
            }
            AtlasRequest::Search(s) => {
                self.metrics.bump(ReceiptKind::Search);
                self.metrics.served_search(now);
                match self.handle_search(&s, now) {
                    Ok(hits) => {
                        let rh = Bytes32(canon::hash(&canon::to_cbor(&hits).unwrap_or_default()));
                        AtlasResponse::Search(SearchResponse {
                            hits,
                            receipt: self.receipt(request_hash, ReceiptKind::Search, Outcome::Ok, rh),
                        })
                    }
                    Err(e) => AtlasResponse::Search(SearchResponse {
                        hits: vec![],
                        receipt: self.receipt(request_hash, ReceiptKind::Search, Outcome::Rejected(e.to_string()), Bytes32::zero()),
                    }),
                }
            }
            AtlasRequest::Card(c) => {
                self.metrics.bump(ReceiptKind::Card);
                let card = self.store.get_card(&c.agent_id).ok().flatten();
                let revocation = self.store.get_revocation(&c.agent_id).ok().flatten();
                let outcome = if card.is_none() && revocation.is_none() {
                    Outcome::NotFound
                } else {
                    Outcome::Ok
                };
                let rh = Bytes32(canon::hash(&canon::to_cbor(&(&card, &revocation)).unwrap_or_default()));
                AtlasResponse::Card(CardResponse {
                    card,
                    revocation,
                    receipt: self.receipt(request_hash, ReceiptKind::Card, outcome, rh),
                })
            }
            AtlasRequest::Challenge(ch) => {
                self.metrics.bump(ReceiptKind::Challenge);
                let (proof, outcome) = match self.handle_challenge(&ch, now) {
                    Ok(p) => (p, Outcome::Ok),
                    Err(e) => (ChallengeProof::Missing, Outcome::Rejected(e.to_string())),
                };
                let rh = Bytes32(canon::hash(&canon::to_cbor(&proof).unwrap_or_default()));
                AtlasResponse::Challenge(ChallengeResponse {
                    proof,
                    receipt: self.receipt(request_hash, ReceiptKind::Challenge, outcome, rh),
                })
            }
            AtlasRequest::Sync(s) => {
                self.metrics.bump(ReceiptKind::Sync);
                let (missing, have) = self.handle_sync(&s);
                let rh = Bytes32(canon::hash(&canon::to_cbor(&missing).unwrap_or_default()));
                AtlasResponse::Sync(SyncResponse {
                    missing,
                    have,
                    receipt: self.receipt(request_hash, ReceiptKind::Sync, Outcome::Ok, rh),
                })
            }
            AtlasRequest::Inbox(i) => {
                self.metrics.bump(ReceiptKind::Inbox);
                match self.handle_inbox(i, now) {
                    Ok(messages) => {
                        let rh = Bytes32(canon::hash(&canon::to_cbor(&messages).unwrap_or_default()));
                        AtlasResponse::Inbox(InboxResponse {
                            messages,
                            receipt: self.receipt(request_hash, ReceiptKind::Inbox, Outcome::Ok, rh),
                        })
                    }
                    Err(e) => AtlasResponse::Inbox(InboxResponse {
                        messages: vec![],
                        receipt: self.receipt(request_hash, ReceiptKind::Inbox, Outcome::Rejected(e), Bytes32::zero()),
                    }),
                }
            }
            AtlasRequest::Vault(v) => {
                self.metrics.bump(ReceiptKind::Vault);
                let is_get = matches!(v, VaultRequest::Get { .. });
                match self.handle_vault(v, now) {
                    Ok(shard) => {
                        let outcome = if is_get && shard.is_none() { Outcome::NotFound } else { Outcome::Ok };
                        let rh = Bytes32(canon::hash(&canon::to_cbor(&shard).unwrap_or_default()));
                        AtlasResponse::Vault(VaultResponse {
                            shard,
                            receipt: self.receipt(request_hash, ReceiptKind::Vault, outcome, rh),
                        })
                    }
                    Err(e) => AtlasResponse::Vault(VaultResponse {
                        shard: None,
                        receipt: self.receipt(request_hash, ReceiptKind::Vault, Outcome::Rejected(e), Bytes32::zero()),
                    }),
                }
            }
            AtlasRequest::Ledger(l) => {
                self.metrics.bump(ReceiptKind::Ledger);
                let entries = self.ledger.range(l.from_seq, (l.limit as usize).min(1000)).unwrap_or_default();
                let root = self.ledger.root();
                let rh = Bytes32(canon::hash(&canon::to_cbor(&(&entries, &root)).unwrap_or_default()));
                AtlasResponse::Ledger(LedgerResponse {
                    entries,
                    root,
                    size: self.ledger.len(),
                    receipt: self.receipt(request_hash, ReceiptKind::Ledger, Outcome::Ok, rh),
                })
            }
        }
    }

    fn check_quota(&self, cert: &OperatorCert, agent: &AgentId, now: u64) -> CoreResult<()> {
        if !self.enforce_quota {
            return Ok(());
        }
        let mut t = self.trust.write();
        let op = cert.operator_pubkey;
        t.operator_nodes.entry(op).or_default().insert(cert.node_pubkey);
        let first = *t.operator_first_seen.entry(op).or_insert(now);
        let agents = t.operator_agents.entry(op).or_default();
        if agents.contains(agent) {
            return Ok(());
        }
        let nodes: Vec<PublicKey> = t.operator_nodes.get(&op).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        let seniority: u32 = nodes.iter().map(|n| t.book.seniority(n, now)).sum();
        let c = Contribution {
            seniority_days: seniority,
            proven_bytes: 0,
            first_seen: first,
        };
        let agents = t.operator_agents.entry(op).or_default();
        if !quota::can_publish(&c, now, agents.len() as u64) {
            return Err(CoreError::Quota);
        }
        agents.insert(agent.clone());
        Ok(())
    }

    fn handle_store(&self, s: StoreRequest, now: u64) -> CoreResult<()> {
        match s {
            StoreRequest::Card(card) => {
                validate::card(&card, now, self.model())?;
                self.check_quota(&card.operator_cert, &card.agent_id, now)?;
                if !self.capacity.read().accepts_new() && self.store.get_card(&card.agent_id).map_err(core_err)?.is_none() {
                    return Err(CoreError::Other("overflow: node above 80 % fill".into()));
                }
                let prev = self.store.put_card(&card).map_err(core_err)?;
                self.sync_targets.write().insert(ids::card_key(&card.agent_id), SyncTarget::Card);
                debug!(agent = %card.agent_id, version = card.version, ?prev, "stored card");
                Ok(())
            }
            StoreRequest::Zone {
                map_version,
                zone_id,
                card,
                trait_indices,
            } => {
                if map_version != self.map.version {
                    return Err(CoreError::invalid("map_version", format!("this node runs map v{}", self.map.version)));
                }
                if zone_id as usize >= self.map.zones() {
                    return Err(CoreError::invalid("zone_id", "out of range"));
                }
                validate::card(&card, now, self.model())?;
                self.check_quota(&card.operator_cert, &card.agent_id, now)?;
                if trait_indices.is_empty() || trait_indices.iter().any(|i| *i as usize >= card.traits.len()) {
                    return Err(CoreError::invalid("trait_indices", "empty or out of range"));
                }
                let zr = ZoneRef { map_version, zone_id };
                // recompute every vector ourselves and refuse misplaced traits
                let texts: Vec<&str> = trait_indices.iter().map(|i| card.traits[*i as usize].as_str()).collect();
                let vectors = self.embedder.embed_batch(&texts).map_err(|e| CoreError::Other(e.to_string()))?;
                for (i, v) in trait_indices.iter().zip(&vectors) {
                    if !self.map.belongs(v, zone_id).map_err(|e| CoreError::Other(e.to_string()))? {
                        return Err(CoreError::invalid("trait", format!("trait {i} does not belong to zone {zone_id}")));
                    }
                }
                let existing = self.store.agent_entries_in_zone(zr, &card.agent_id);
                let is_new = existing.is_empty();
                if is_new && !self.capacity.read().accepts_new() {
                    return Err(CoreError::Other("overflow: node above 80 % fill".into()));
                }
                // never accept a version older than the newest we have seen for this agent, nor a revoked one
                if let Some(known) = self.store.get_card(&card.agent_id).map_err(core_err)? {
                    if known.version > card.version {
                        return Err(CoreError::StaleVersion {
                            got: card.version,
                            known: known.version,
                        });
                    }
                }
                if let Some(r) = self.store.get_revocation(&card.agent_id).map_err(core_err)? {
                    if let RevocationTarget::Card(v) = r.target {
                        if card.version <= v {
                            return Err(CoreError::StaleVersion { got: card.version, known: v });
                        }
                    }
                }
                if let Some(e) = existing.iter().find(|e| !e.is_ephemeral()) {
                    if e.card_version > card.version {
                        return Err(CoreError::StaleVersion {
                            got: card.version,
                            known: e.card_version,
                        });
                    }
                }
                // keep the signed card so that sync can re-emit verifiable material
                match self.store.put_card(&card) {
                    Ok(_) => {}
                    Err(alp_grid_store::StoreError::Core(CoreError::StaleVersion { .. })) => {}
                    Err(e) => return Err(core_err(e)),
                }
                // drop traits that vanished or belong to an older version
                self.store
                    .remove_agent_entries(&card.agent_id, Some(card.version.saturating_sub(1)), None)
                    .map_err(core_err)?;
                let keep: HashSet<u8> = trait_indices.iter().cloned().collect();
                let stale: Vec<Vec<u8>> = self
                    .store
                    .agent_entries_in_zone(zr, &card.agent_id)
                    .into_iter()
                    .filter(|e| !e.is_ephemeral() && !keep.contains(&e.trait_index))
                    .map(|e| e.key())
                    .collect();
                if !stale.is_empty() {
                    self.store.remove_zone_entries(zr, &stale).map_err(core_err)?;
                }
                for (i, v) in trait_indices.iter().zip(vectors) {
                    let entry = ZoneEntry::from_card(&card, *i).expect("index checked");
                    self.store.put_zone_entry(zr, entry, v).map_err(core_err)?;
                }
                self.sync_targets.write().insert(ids::zone_key(map_version, zone_id), SyncTarget::Zone(zr));
                Ok(())
            }
            StoreRequest::Ephemeral {
                map_version,
                zone_id,
                ephemeral,
            } => {
                if map_version != self.map.version {
                    return Err(CoreError::invalid("map_version", "wrong map version"));
                }
                validate::ephemeral(&ephemeral, now)?;
                let v = self.embedder.embed(&ephemeral.text).map_err(|e| CoreError::Other(e.to_string()))?;
                if !self.map.belongs(&v, zone_id).map_err(|e| CoreError::Other(e.to_string()))? {
                    return Err(CoreError::invalid("text", "does not belong to this zone"));
                }
                let active = self
                    .store
                    .zones_held()
                    .iter()
                    .flat_map(|(z, _)| self.store.agent_entries_in_zone(*z, &ephemeral.agent_id))
                    .filter(|e| e.is_ephemeral() && e.expires_at > now)
                    .filter(|e| !matches!(&e.kind, EntryKind::Ephemeral { ephemeral_id, .. } if *ephemeral_id == ephemeral.ephemeral_id))
                    .count();
                if active >= EPHEMERAL_MAX_ACTIVE {
                    return Err(CoreError::invalid("ephemeral", "too many active announcements"));
                }
                let card_version = self.store.get_card(&ephemeral.agent_id).ok().flatten().map(|c| c.version).unwrap_or(0);
                let zr = ZoneRef { map_version, zone_id };
                self.store
                    .put_zone_entry(zr, ZoneEntry::from_ephemeral(&ephemeral, card_version), v)
                    .map_err(core_err)?;
                self.sync_targets.write().insert(ids::zone_key(map_version, zone_id), SyncTarget::Zone(zr));
                Ok(())
            }
            StoreRequest::Revocation(r) => {
                match self.store.get_card(&r.agent_id).map_err(core_err)? {
                    Some(card) => validate::revocation_against_card(&r, &card)?,
                    None => {
                        if r.by == RevokedBy::Operator {
                            return Err(CoreError::invalid("revocation", "operator revocation for an unknown card"));
                        }
                        validate::revocation_standalone(&r)?;
                    }
                }
                self.store.put_revocation(&r).map_err(core_err)?;
                if r.by == RevokedBy::Operator {
                    self.ledger.append(LedgerEvent::Revocation(r.clone()), now)?;
                }
                info!(agent = %r.agent_id, ?r.target, "revocation applied");
                Ok(())
            }
        }
    }

    fn handle_search(&self, s: &SearchRequest, now: u64) -> CoreResult<Vec<SearchHit>> {
        if s.map_version != self.map.version {
            return Err(CoreError::invalid("map_version", "wrong map version"));
        }
        if s.vector.dim() != self.map.dim {
            return Err(CoreError::invalid("vector", "wrong dimension"));
        }
        let k = s.k.clamp(1, SEARCH_MAX_K) as usize;
        validate::filters(&s.filters)?;
        Ok(self.store.search(
            ZoneRef {
                map_version: s.map_version,
                zone_id: s.zone_id,
            },
            &s.vector,
            &s.filters,
            s.at,
            k,
            now,
        ))
    }

    fn known_pubkeys(&self) -> Vec<PublicKey> {
        let mut v: Vec<PublicKey> = self
            .transport
            .read()
            .as_ref()
            .map(|t| t.known().into_iter().map(|n| n.pubkey).collect())
            .unwrap_or_default();
        v.push(self.identity.node.public());
        v
    }

    fn handle_challenge(&self, ch: &Challenge, now: u64) -> CoreResult<ChallengeProof> {
        let me = self.identity.node.public();
        challenge::verify_challenge(ch, &me, &self.known_pubkeys(), challenge::local_round(now))?;
        Ok(match &ch.kind {
            ChallengeKind::Storage { agent_id } => match self.store.get_card(agent_id).map_err(core_err)? {
                Some(c) => ChallengeProof::Card(c),
                None => ChallengeProof::Missing,
            },
            ChallengeKind::Service { map_version, zone_id, vector } => {
                let hits = self.store.search(
                    ZoneRef {
                        map_version: *map_version,
                        zone_id: *zone_id,
                    },
                    vector,
                    &Filters::default(),
                    None,
                    10,
                    now,
                );
                ChallengeProof::Hits(hits)
            }
        })
    }

    /// What we hold under a key, as (hash, how to re-emit it).
    fn items_for_key(&self, key: &Position) -> Vec<(Bytes32, StoreRequest)> {
        let target = self.sync_targets.read().get(key).copied();
        match target {
            Some(SyncTarget::Zone(zr)) => self
                .store
                .zone_entries(zr)
                .into_iter()
                .filter(|se| !se.entry.is_ephemeral())
                .filter_map(|se| {
                    let h = Bytes32(canon::hash(&canon::to_cbor(&se.entry).unwrap_or_default()));
                    let card = self.store.get_card(&se.entry.agent_id).ok().flatten()?;
                    if card.version != se.entry.card_version {
                        return None;
                    }
                    Some((
                        h,
                        StoreRequest::Zone {
                            map_version: zr.map_version,
                            zone_id: zr.zone_id,
                            card,
                            trait_indices: vec![se.entry.trait_index],
                        },
                    ))
                })
                .collect(),
            Some(SyncTarget::Card) => self
                .store
                .list_cards(5000)
                .unwrap_or_default()
                .into_iter()
                .filter(|c| ids::card_key(&c.agent_id) == *key)
                .map(|c| (c.hash().unwrap_or_default(), StoreRequest::Card(c)))
                .collect(),
            None => vec![],
        }
    }

    fn handle_sync(&self, s: &SyncRequest) -> (Vec<StoreRequest>, Vec<Bytes32>) {
        let theirs: HashSet<Bytes32> = s.have.iter().cloned().collect();
        let items = self.items_for_key(&s.key);
        let have: Vec<Bytes32> = items.iter().map(|(h, _)| *h).collect();
        let missing: Vec<StoreRequest> = items.into_iter().filter(|(h, _)| !theirs.contains(h)).map(|(_, r)| r).take(500).collect();
        (missing, have)
    }

    fn handle_inbox(&self, i: InboxRequest, now: u64) -> Result<Vec<InboxMessage>, String> {
        match i {
            InboxRequest::Deposit(m) => {
                let pending = self
                    .store
                    .inbox_list(&m.to)
                    .map_err(|e| e.to_string())?
                    .iter()
                    .filter(|x| x.from_pubkey == m.from_pubkey)
                    .count();
                alp_grid_inbox::verify_message(&m, now, pending).map_err(|e| e.to_string())?;
                self.store.inbox_put(&m).map_err(|e| e.to_string())?;
                Ok(vec![])
            }
            InboxRequest::Fetch {
                agent_id,
                agent_pubkey,
                nonce,
                auth,
            } => {
                alp_grid_inbox::verify_fetch(&agent_id, &agent_pubkey, nonce, &auth).map_err(|e| e.to_string())?;
                let msgs = self.store.inbox_list(&agent_id).map_err(|e| e.to_string())?;
                Ok(msgs.into_iter().filter(|m| m.expires_at > now).collect())
            }
            InboxRequest::Ack(a) => {
                alp_grid_inbox::verify_ack(&a).map_err(|e| e.to_string())?;
                self.store.inbox_remove(&a.agent_id, &a.message_ids).map_err(|e| e.to_string())?;
                Ok(vec![])
            }
        }
    }

    fn handle_vault(&self, v: VaultRequest, now: u64) -> Result<Option<VaultShard>, String> {
        match v {
            VaultRequest::Put(shard) => {
                alp_grid_vault::verify_shard(&shard, now).map_err(|e| e.to_string())?;
                let used = self.store.vault_bytes_for(&shard.agent_id).map_err(|e| e.to_string())?;
                if used + shard.data.0.len() as u64 > VAULT_MAX_BYTES {
                    return Err("vault quota exceeded for this agent".into());
                }
                self.store.vault_put(&shard).map_err(|e| e.to_string())?;
                Ok(None)
            }
            VaultRequest::Get { agent_id, snapshot, index } => self.store.vault_get(&agent_id, snapshot, index).map_err(|e| e.to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // Publisher / searcher side
    // -----------------------------------------------------------------------

    async fn guardians(&self, key: &Position, k: usize) -> Vec<NodeRef> {
        let t = self.transport.read().clone();
        match t {
            Some(t) => {
                let mut g = t.closest(key, k).await;
                if g.is_empty() {
                    g.push(self.me());
                }
                g
            }
            None => vec![self.me()],
        }
    }

    /// Send a request to one node; the local node is answered in-process.
    pub async fn request(&self, to: &NodeRef, req: AtlasRequest) -> Result<AtlasResponse, TransportError> {
        if to.pubkey == self.identity.node.public() {
            return Ok(self.handle(Some(self.me()), req));
        }
        let t = self
            .transport
            .read()
            .clone()
            .ok_or_else(|| TransportError::Unreachable("no transport".into()))?;
        let started = Instant::now();
        let res = t.request(to, req.clone()).await;
        let latency = started.elapsed().as_millis() as f32;
        match &res {
            Ok(resp) => {
                let ok = self.verify_receipt(to, &req, resp);
                self.trust.write().rep.note_receipt(to.pubkey, ok, latency);
                if ok {
                    self.metrics.receipts_ok.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.metrics.receipts_bad.fetch_add(1, Ordering::Relaxed);
                    return Err(TransportError::Protocol("invalid receipt".into()));
                }
            }
            Err(TransportError::Timeout) => self.trust.write().rep.note_timeout(to.pubkey),
            Err(_) => {}
        }
        res
    }

    fn verify_receipt(&self, from: &NodeRef, req: &AtlasRequest, resp: &AtlasResponse) -> bool {
        let Some(r) = resp.receipt() else { return false };
        if r.node_pubkey != from.pubkey || r.verify().is_err() {
            return false;
        }
        let req_hash = Bytes32(canon::hash(&canon::to_cbor(req).unwrap_or_default()));
        if r.request_hash != req_hash {
            return false;
        }
        // bind the answer: the response hash must match the payload we received
        let payload_hash = match resp {
            AtlasResponse::Search(s) => Some(canon::hash(&canon::to_cbor(&s.hits).unwrap_or_default())),
            AtlasResponse::Card(c) => Some(canon::hash(&canon::to_cbor(&(&c.card, &c.revocation)).unwrap_or_default())),
            AtlasResponse::Challenge(c) => Some(canon::hash(&canon::to_cbor(&c.proof).unwrap_or_default())),
            AtlasResponse::Sync(s) => Some(canon::hash(&canon::to_cbor(&s.missing).unwrap_or_default())),
            AtlasResponse::Inbox(i) => Some(canon::hash(&canon::to_cbor(&i.messages).unwrap_or_default())),
            AtlasResponse::Vault(v) => Some(canon::hash(&canon::to_cbor(&v.shard).unwrap_or_default())),
            AtlasResponse::Ledger(l) => Some(canon::hash(&canon::to_cbor(&(&l.entries, &l.root)).unwrap_or_default())),
            AtlasResponse::Store(_) => None,
            AtlasResponse::Error(_) => None,
        };
        match payload_hash {
            Some(h) => r.response_hash == Bytes32(h) || !matches!(r.outcome, Outcome::Ok),
            None => true,
        }
    }

    async fn fan_out(&self, targets: &[NodeRef], req: AtlasRequest) -> Vec<(NodeRef, Result<AtlasResponse, TransportError>)> {
        let futs = targets.iter().map(|t| {
            let req = req.clone();
            async move { (t.clone(), self.request(t, req).await) }
        });
        join_all(futs).await
    }

    fn count_ok(results: &[(NodeRef, Result<AtlasResponse, TransportError>)], rejections: &mut Vec<String>) -> usize {
        let mut ok = 0;
        for (n, r) in results {
            match r {
                Ok(resp) => match resp.receipt().map(|r| &r.outcome) {
                    Some(Outcome::Ok) => ok += 1,
                    Some(Outcome::Rejected(reason)) => rejections.push(format!("{}: {reason}", &n.pubkey.to_hex()[..8])),
                    Some(Outcome::NotFound) => rejections.push(format!("{}: not found", &n.pubkey.to_hex()[..8])),
                    None => rejections.push(format!("{}: no receipt", &n.pubkey.to_hex()[..8])),
                },
                Err(e) => rejections.push(format!("{}: {e}", &n.pubkey.to_hex()[..8])),
            }
        }
        ok
    }

    /// Zones (per trait index) of a card, computed with our embedder and map.
    pub fn zones_of(&self, texts: &[String]) -> CoreResult<HashMap<u32, Vec<u8>>> {
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        let vectors = self.embedder.embed_batch(&refs).map_err(|e| CoreError::Other(e.to_string()))?;
        let mut groups: HashMap<u32, Vec<u8>> = HashMap::new();
        for (i, v) in vectors.iter().enumerate() {
            let a = self.map.assign(v).map_err(|e| CoreError::Other(e.to_string()))?;
            for z in a.zones() {
                groups.entry(z).or_default().push(i as u8);
            }
        }
        Ok(groups)
    }

    /// Publish a card handed by a local agent (agent-signed). The node validates, countersigns, fans out.
    pub async fn publish_card(&self, mut card: Card) -> CoreResult<PublishReport> {
        let started = Instant::now();
        let now = self.now();
        if card.operator_cert != self.identity.cert {
            // the agent may not know our certificate yet: fill it in before checking the agent signature?
            // No: the certificate is agent-signed. The SDK fetches it from /v1/status first.
            return Err(CoreError::invalid(
                "operator_cert",
                "card must carry this node's operator certificate (see GET /v1/status)",
            ));
        }
        validate::card_before_countersign(&card, now, self.model())?;
        self.check_quota(&card.operator_cert, &card.agent_id, now)?;
        card.countersign(&self.identity.node, now)?;
        self.remember_own(&card.agent_id);
        self.metrics.publishes_made.fetch_add(1, Ordering::Relaxed);
        let report = self.fan_out_card(&card).await;
        let mut report = report?;
        report.took_ms = started.elapsed().as_millis() as u64;
        Ok(report)
    }

    async fn fan_out_card(&self, card: &Card) -> CoreResult<PublishReport> {
        let groups = self.zones_of(&card.traits)?;
        let card_targets = self.guardians(&ids::card_key(&card.agent_id), REPLICATION).await;
        let mut rejections = Vec::new();
        let card_results = self.fan_out(&card_targets, AtlasRequest::Store(StoreRequest::Card(card.clone()))).await;
        let card_copies = Self::count_ok(&card_results, &mut rejections);
        let zone_futs = groups.iter().map(|(zone_id, idx)| async move {
            let targets = self.guardians(&ids::zone_key(self.map.version, *zone_id), REPLICATION).await;
            let res = self
                .fan_out(
                    &targets,
                    AtlasRequest::Store(StoreRequest::Zone {
                        map_version: self.map.version,
                        zone_id: *zone_id,
                        card: card.clone(),
                        trait_indices: idx.clone(),
                    }),
                )
                .await;
            (*zone_id, targets.len(), res)
        });
        let mut zones = Vec::new();
        for (zone_id, targets, res) in join_all(zone_futs).await {
            let copies = Self::count_ok(&res, &mut rejections);
            zones.push(ZoneReport { zone_id, copies, targets });
        }
        zones.sort_by_key(|z| z.zone_id);
        Ok(PublishReport {
            agent_id: Some(card.agent_id.clone()),
            version: Some(card.version),
            card_copies,
            card_targets: card_targets.len(),
            zones,
            rejections,
            took_ms: 0,
        })
    }

    /// Re-countersign and re-send our agents' cards whose `last_seen` is older than 24 h.
    pub async fn republish_due(&self) -> Vec<PublishReport> {
        let now = self.now();
        let mut out = Vec::new();
        for id in self.own_agents() {
            if let Ok(Some(mut card)) = self.store.get_card(&id) {
                if card.last_seen + CARD_REPUBLISH <= now && card.expires_at > now && card.countersign(&self.identity.node, now).is_ok() {
                    if let Ok(r) = self.fan_out_card(&card).await {
                        out.push(r);
                    }
                }
            }
        }
        out
    }

    pub async fn publish_ephemeral(&self, mut e: Ephemeral) -> CoreResult<PublishReport> {
        let started = Instant::now();
        let now = self.now();
        if e.operator_cert != self.identity.cert {
            return Err(CoreError::invalid("operator_cert", "ephemeral must carry this node's operator certificate"));
        }
        validate::ephemeral_before_countersign(&e, now)?;
        e.countersign(&self.identity.node)?;
        let groups = self.zones_of(&[e.text.clone()])?;
        let mut rejections = Vec::new();
        let mut zones = Vec::new();
        for zone_id in groups.keys() {
            let targets = self.guardians(&ids::zone_key(self.map.version, *zone_id), REPLICATION).await;
            let res = self
                .fan_out(
                    &targets,
                    AtlasRequest::Store(StoreRequest::Ephemeral {
                        map_version: self.map.version,
                        zone_id: *zone_id,
                        ephemeral: e.clone(),
                    }),
                )
                .await;
            let copies = Self::count_ok(&res, &mut rejections);
            zones.push(ZoneReport {
                zone_id: *zone_id,
                copies,
                targets: targets.len(),
            });
        }
        Ok(PublishReport {
            agent_id: Some(e.agent_id.clone()),
            version: None,
            card_copies: 0,
            card_targets: 0,
            zones,
            rejections,
            took_ms: started.elapsed().as_millis() as u64,
        })
    }

    pub async fn publish_revocation(&self, r: Revocation) -> CoreResult<PublishReport> {
        let started = Instant::now();
        r.verify_sig()?;
        // the card guardians, plus the zone guardians of every trait we know of
        let mut targets: Vec<NodeRef> = self.guardians(&ids::card_key(&r.agent_id), REPLICATION).await;
        let known = match self.store.get_card(&r.agent_id) {
            Ok(Some(c)) => Some(c),
            _ => self.get_card(&r.agent_id).await.ok().and_then(|(c, _)| c),
        };
        if let Some(card) = known {
            for zone_id in self.zones_of(&card.traits)?.keys() {
                for n in self.guardians(&ids::zone_key(self.map.version, *zone_id), REPLICATION).await {
                    if !targets.contains(&n) {
                        targets.push(n);
                    }
                }
            }
        }
        let mut rejections = Vec::new();
        let res = self.fan_out(&targets, AtlasRequest::Store(StoreRequest::Revocation(r.clone()))).await;
        let copies = Self::count_ok(&res, &mut rejections);
        Ok(PublishReport {
            agent_id: Some(r.agent_id.clone()),
            version: None,
            card_copies: copies,
            card_targets: targets.len(),
            zones: vec![],
            rejections,
            took_ms: started.elapsed().as_millis() as u64,
        })
    }

    /// Query one zone: ask up to 3 guardians (seniors first), keep the first valid answer.
    async fn search_zone(&self, zone_id: u32, vector: &Vector, filters: &Filters, at: Option<u64>, k: u16) -> Option<Vec<SearchHit>> {
        let mut guardians = self.guardians(&ids::zone_key(self.map.version, zone_id), REPLICATION).await;
        {
            let t = self.trust.read();
            let now = self.now();
            guardians.sort_by(|a, b| {
                let ta = if a.pubkey == self.identity.node.public() {
                    2.0
                } else {
                    t.rep.trust(&a.pubkey, &t.book, now)
                };
                let tb = if b.pubkey == self.identity.node.public() {
                    2.0
                } else {
                    t.rep.trust(&b.pubkey, &t.book, now)
                };
                tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        guardians.truncate(GUARDIANS_PER_ZONE_QUERIED);
        let req = AtlasRequest::Search(SearchRequest {
            map_version: self.map.version,
            zone_id,
            vector: vector.clone(),
            filters: filters.clone(),
            at,
            k,
        });
        let mut futs: Vec<_> = guardians
            .iter()
            .map(|g| {
                let req = req.clone();
                Box::pin(async move { tokio::time::timeout(Duration::from_millis(SEARCH_TIMEOUT_MS), self.request(g, req)).await })
            })
            .collect();
        while !futs.is_empty() {
            let (res, _idx, rest) = futures::future::select_all(futs).await;
            futs = rest;
            if let Ok(Ok(AtlasResponse::Search(s))) = res {
                if matches!(s.receipt.outcome, Outcome::Ok) {
                    return Some(s.hits);
                }
            }
        }
        None
    }

    pub async fn search(&self, q: SearchQuery) -> CoreResult<SearchResult> {
        let started = Instant::now();
        let now = self.now();
        self.metrics.searches_made.fetch_add(1, Ordering::Relaxed);
        let k = q.k.unwrap_or(10).clamp(1, SEARCH_MAX_K);
        validate::filters(&q.filters)?;
        let mut vector = match (&q.text, &q.vector) {
            (Some(t), _) if !t.trim().is_empty() => self.embedder.embed(t.trim()).map_err(|e| CoreError::Other(e.to_string()))?,
            (_, Some(v)) => v.clone(),
            _ => return Err(CoreError::invalid("query", "text or vector required")),
        };
        if vector.dim() != self.map.dim {
            return Err(CoreError::invalid("vector", "wrong dimension"));
        }
        vector.normalize();
        let cache_key = if q.at.is_none() {
            Some(Bytes32(canon::hash(&canon::to_cbor(&(&vector, &q.filters, k)).unwrap_or_default())))
        } else {
            None
        };
        if let Some(ck) = &cache_key {
            if let Some((t, r)) = self.search_cache.lock().get(ck) {
                if t + SEARCH_CACHE_SECS > now {
                    let mut r = r.clone();
                    r.cached = true;
                    r.took_ms = started.elapsed().as_millis() as u64;
                    return Ok(r);
                }
            }
        }
        let near = self
            .map
            .nearest(&vector, self.nprobe.load(Ordering::Relaxed))
            .map_err(|e| CoreError::Other(e.to_string()))?;
        let mut zones: Vec<u32> = near.iter().map(|z| z.zone_id).collect();
        let decoys = self.map.decoys(
            (now / 60) ^ u64::from_le_bytes(cache_key.map(|c| c.0[..8].try_into().unwrap()).unwrap_or([0; 8])),
            DECOY_ZONES,
            &zones,
        );
        zones.extend(decoys);
        let per_zone_k = k.max(10);
        let futs = zones.iter().map(|z| self.search_zone(*z, &vector, &q.filters, q.at, per_zone_k));
        let answers = join_all(futs).await;
        let guardians_answered = answers.iter().filter(|a| a.is_some()).count();
        let mut by_agent: HashMap<AgentId, Vec<SearchHit>> = HashMap::new();
        for hits in answers.into_iter().flatten() {
            for h in hits {
                by_agent.entry(h.agent_id.clone()).or_default().push(h);
            }
        }
        let mut results: Vec<AgentResult> = by_agent
            .into_iter()
            .map(|(agent_id, mut hits)| {
                hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
                hits.dedup_by(|a, b| a.trait_index == b.trait_index && a.kind == b.kind);
                let best = hits[0].score;
                let others: f32 = hits.iter().skip(1).map(|h| h.score).filter(|s| *s > 0.6).sum();
                let last_seen = hits.iter().map(|h| h.last_seen).max().unwrap_or(0);
                let fresh = if last_seen + alp_grid_core::time::DAY > now {
                    0.05
                } else if last_seen + 7 * alp_grid_core::time::DAY > now {
                    0.02
                } else {
                    0.0
                };
                let eph = if q.at.is_some() && hits.iter().any(|h| matches!(h.kind, EntryKind::Ephemeral { .. })) {
                    0.1
                } else {
                    0.0
                };
                AgentResult {
                    agent_id,
                    card_version: hits.iter().map(|h| h.card_version).max().unwrap_or(0),
                    score: best + 0.5 * others + fresh + eph,
                    last_seen,
                    best_trait: hits[0].text.clone(),
                    matches: hits,
                }
            })
            .collect();
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(k as usize);
        let result = SearchResult {
            results,
            zones_queried: zones,
            guardians_answered,
            cached: false,
            took_ms: started.elapsed().as_millis() as u64,
        };
        if let Some(ck) = cache_key {
            let mut c = self.search_cache.lock();
            if c.len() > 10_000 {
                c.clear();
            }
            c.insert(ck, (now, result.clone()));
        }
        Ok(result)
    }

    pub async fn get_card(&self, agent_id: &AgentId) -> CoreResult<(Option<Card>, Option<Revocation>)> {
        if let (Ok(c), Ok(r)) = (self.store.get_card(agent_id), self.store.get_revocation(agent_id)) {
            if c.is_some() || r.is_some() {
                return Ok((c, r));
            }
        }
        let mut guardians = self.guardians(&ids::card_key(agent_id), REPLICATION).await;
        guardians.truncate(GUARDIANS_PER_ZONE_QUERIED);
        let res = self.fan_out(&guardians, AtlasRequest::Card(CardRequest { agent_id: agent_id.clone() })).await;
        let now = self.now();
        let mut best: Option<Card> = None;
        let mut rev: Option<Revocation> = None;
        for (_, r) in res {
            if let Ok(AtlasResponse::Card(c)) = r {
                if let Some(card) = c.card {
                    if validate::card(&card, now, self.model()).is_ok() && best.as_ref().map(|b| card.version > b.version).unwrap_or(true) {
                        best = Some(card);
                    }
                }
                if let Some(r) = c.revocation {
                    if r.verify_sig().is_ok() {
                        rev = Some(r);
                    }
                }
            }
        }
        if let (Some(c), Some(r)) = (&best, &rev) {
            if let RevocationTarget::Card(v) = r.target {
                if c.version <= v {
                    best = None;
                }
            }
        }
        Ok((best, rev))
    }

    pub async fn inbox_deposit(&self, to: AgentId, from_pubkey: PublicKey, sealed: Vec<u8>) -> CoreResult<DepositReport> {
        let now = self.now();
        let mut m = alp_grid_inbox::new_message(to.clone(), from_pubkey, sealed, now, &self.identity.cert);
        alp_grid_inbox::countersign(&mut m, &self.identity.node).map_err(|e| CoreError::Other(e.to_string()))?;
        let targets = self.guardians(&ids::inbox_key(&to), REPLICATION).await;
        let mut rejections = Vec::new();
        let res = self.fan_out(&targets, AtlasRequest::Inbox(InboxRequest::Deposit(m.clone()))).await;
        let copies = Self::count_ok(&res, &mut rejections);
        if copies == 0 {
            return Err(CoreError::Other(format!("no guardian accepted the message: {}", rejections.join("; "))));
        }
        Ok(DepositReport {
            message_id: m.message_id,
            copies,
            targets: targets.len(),
        })
    }

    pub async fn inbox_fetch(&self, agent_id: AgentId, agent_pubkey: PublicKey, nonce: u64, auth: alp_grid_core::Bytes64) -> CoreResult<Vec<InboxMessage>> {
        let targets = self.guardians(&ids::inbox_key(&agent_id), REPLICATION).await;
        let res = self
            .fan_out(
                &targets,
                AtlasRequest::Inbox(InboxRequest::Fetch {
                    agent_id,
                    agent_pubkey,
                    nonce,
                    auth,
                }),
            )
            .await;
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (_, r) in res {
            if let Ok(AtlasResponse::Inbox(i)) = r {
                for m in i.messages {
                    if seen.insert(m.message_id) {
                        out.push(m);
                    }
                }
            }
        }
        out.sort_by_key(|m| m.deposited_at);
        Ok(out)
    }

    pub async fn inbox_ack(&self, ack: InboxAck) -> CoreResult<usize> {
        alp_grid_inbox::verify_ack(&ack).map_err(|e| CoreError::Other(e.to_string()))?;
        let targets = self.guardians(&ids::inbox_key(&ack.agent_id), REPLICATION).await;
        let res = self.fan_out(&targets, AtlasRequest::Inbox(InboxRequest::Ack(ack))).await;
        Ok(Self::count_ok(&res, &mut vec![]))
    }

    pub async fn vault_put(&self, mut shards: Vec<VaultShard>) -> CoreResult<VaultPutReport> {
        let Some(first) = shards.first() else {
            return Err(CoreError::invalid("shards", "empty"));
        };
        let snapshot = first.snapshot;
        let total = shards.len();
        let mut stored = 0;
        for s in shards.iter_mut() {
            if s.operator_cert != self.identity.cert {
                return Err(CoreError::invalid("operator_cert", "shards must carry this node's operator certificate"));
            }
            alp_grid_vault::countersign(s, &self.identity.node).map_err(|e| CoreError::Other(e.to_string()))?;
        }
        let futs = shards.iter().map(|s| async move {
            let targets = self.guardians(&ids::vault_shard_key(&s.agent_id, s.snapshot, s.index), 1).await;
            let res = self.fan_out(&targets, AtlasRequest::Vault(VaultRequest::Put(s.clone()))).await;
            Self::count_ok(&res, &mut vec![]) > 0
        });
        for ok in join_all(futs).await {
            if ok {
                stored += 1;
            }
        }
        Ok(VaultPutReport {
            snapshot,
            shards_stored: stored,
            shards_total: total,
        })
    }

    pub async fn vault_get(&self, agent_id: AgentId, snapshot: u64) -> CoreResult<VaultGetReport> {
        let futs = (0..VAULT_SHARDS as u8).map(|i| {
            let agent_id = agent_id.clone();
            async move {
                let targets = self.guardians(&ids::vault_shard_key(&agent_id, snapshot, i), 1).await;
                let res = self
                    .fan_out(&targets, AtlasRequest::Vault(VaultRequest::Get { agent_id, snapshot, index: i }))
                    .await;
                res.into_iter().find_map(|(_, r)| match r {
                    Ok(AtlasResponse::Vault(v)) => v.shard.filter(|s| Bytes32(canon::hash(&s.data.0)) == s.shard_hash).map(|s| s.data.0),
                    _ => None,
                })
            }
        });
        let shards: Vec<Option<Vec<u8>>> = join_all(futs).await;
        let found = shards.iter().filter(|s| s.is_some()).count();
        let encrypted = alp_grid_vault::reconstruct(shards).ok().map(Blob);
        Ok(VaultGetReport {
            snapshot,
            shards_found: found,
            encrypted,
        })
    }

    // -----------------------------------------------------------------------
    // Controller side
    // -----------------------------------------------------------------------

    /// Challenge every node we were drawn to control at this round.
    pub async fn run_challenge_round(&self) -> ChallengeRoundReport {
        let now = self.now();
        let round = challenge::local_round(now);
        let known: Vec<NodeRef> = self.transport.read().as_ref().map(|t| t.known()).unwrap_or_default();
        let mut all: Vec<PublicKey> = known.iter().map(|n| n.pubkey).collect();
        let me = self.identity.node.public();
        all.push(me);
        let mut report = ChallengeRoundReport {
            round,
            challenged: 0,
            failed: 0,
        };
        let zones = self.store.zones_held();
        for target in &known {
            if !challenge::is_controller(round, &target.pubkey, &me, &all) {
                continue;
            }
            // a zone we both should hold if any, otherwise a storage challenge on a card we know
            let kind = if let Some((zr, _)) = zones.first() {
                let v = self
                    .store
                    .zone_entries(*zr)
                    .first()
                    .map(|e| e.vector.clone())
                    .unwrap_or_else(|| Vector(vec![1.0; self.map.dim]));
                ChallengeKind::Service {
                    map_version: zr.map_version,
                    zone_id: zr.zone_id,
                    vector: v,
                }
            } else if let Some(c) = self.store.list_cards(1).ok().and_then(|v| v.into_iter().next()) {
                ChallengeKind::Storage { agent_id: c.agent_id }
            } else {
                continue;
            };
            let Ok(ch) = challenge::sign_challenge(&self.identity.node, round, target.pubkey, kind) else {
                continue;
            };
            self.metrics.challenges_sent.fetch_add(1, Ordering::Relaxed);
            report.challenged += 1;
            let res = tokio::time::timeout(Duration::from_millis(CHALLENGE_TIMEOUT_MS), self.request(target, AtlasRequest::Challenge(ch))).await;
            let ok = matches!(res, Ok(Ok(AtlasResponse::Challenge(ref c))) if matches!(c.receipt.outcome, Outcome::Ok));
            {
                let mut t = self.trust.write();
                t.book.record(target.pubkey, now, ok);
                t.rep.note_challenge(target.pubkey, ok);
            }
            if !ok {
                report.failed += 1;
                self.metrics.challenges_failed.fetch_add(1, Ordering::Relaxed);
                let sig = self.identity.node.sign(&challenge::failure_hash(&target.pubkey, round));
                let _ = self.ledger.append(
                    LedgerEvent::ChallengeFailure {
                        node_pubkey: target.pubkey,
                        round,
                        controller_pubkey: me,
                        controller_sig: sig,
                    },
                    now,
                );
                warn!(node = %target.pubkey.to_hex(), round, "challenge failed, recorded in ledger");
            }
        }
        report
    }

    /// Anti-entropy with the other guardians of every key we hold: pull what we lack, push what
    /// they lack (this is how a node that just became a guardian receives its copies).
    pub async fn sync_round(&self) -> usize {
        let keys: Vec<Position> = self.sync_targets.read().keys().cloned().collect();
        let mut imported = 0;
        for key in keys.into_iter().take(256) {
            let items = self.items_for_key(&key);
            let have: Vec<Bytes32> = items.iter().map(|(h, _)| *h).collect();
            let mut peers = self.guardians(&key, REPLICATION).await;
            peers.retain(|p| p.pubkey != self.identity.node.public());
            for p in peers {
                let Ok(AtlasResponse::Sync(s)) = self.request(&p, AtlasRequest::Sync(SyncRequest { key, have: have.clone() })).await else {
                    continue;
                };
                for m in s.missing {
                    if self.handle_store(m, self.now()).is_ok() {
                        imported += 1;
                    }
                }
                let theirs: HashSet<Bytes32> = s.have.into_iter().collect();
                let push: Vec<AtlasRequest> = items
                    .iter()
                    .filter(|(h, _)| !theirs.contains(h))
                    .map(|(_, r)| AtlasRequest::Store(r.clone()))
                    .collect();
                for req in push {
                    if let Ok(resp) = self.request(&p, req).await {
                        if matches!(resp.receipt().map(|r| &r.outcome), Some(Outcome::Ok)) {
                            imported += 1;
                        }
                    }
                }
            }
        }
        // ledger catch-up from a couple of peers
        let known = self.transport.read().as_ref().map(|t| t.known()).unwrap_or_default();
        for p in known.iter().take(2) {
            if let Ok(AtlasResponse::Ledger(l)) = self
                .request(
                    p,
                    AtlasRequest::Ledger(LedgerRequest {
                        from_seq: self.ledger.len(),
                        limit: 500,
                    }),
                )
                .await
            {
                if let Ok(n) = self.ledger.import(&l.entries) {
                    imported += n;
                }
            }
        }
        imported
    }

    pub fn expire_tick(&self) -> usize {
        let now = self.now();
        let n = self.store.expire(now).unwrap_or(0);
        let _ = self.store.receipts_prune(now.saturating_sub(RECEIPT_RETENTION));
        let mut t = self.trust.write();
        for r in t.book.records.values_mut() {
            r.prune(now);
        }
        n
    }
}

fn core_err(e: alp_grid_store::StoreError) -> CoreError {
    match e {
        alp_grid_store::StoreError::Core(c) => c,
        other => CoreError::Other(other.to_string()),
    }
}

impl InboundHandler for Engine {
    fn handle(&self, from: Option<NodeRef>, req: AtlasRequest) -> AtlasResponse {
        Engine::handle(self, from, req)
    }
}

// ---------------------------------------------------------------------------
// Tests: a single node is its own Atlas
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod testing {
    use super::*;
    use alp_grid_core::keys::Bytes64;
    use alp_grid_embed::HashEmbedder;

    pub fn engine(seed: u8, now: u64) -> Arc<Engine> {
        let node = Keypair::from_seed(&[seed; 32]);
        let identity = Identity::self_operated(node, now, 4).unwrap();
        let store = Arc::new(Store::open_temp().unwrap());
        let map = Arc::new(Map::dev(1, 8, 8, 1));
        let embedder: Arc<dyn Embedder> = Arc::new(HashEmbedder::new());
        Arc::new(
            Engine::with_clock(
                identity,
                store,
                map,
                embedder,
                Capacity {
                    declared_bytes: 1 << 30,
                    used_bytes: 0,
                },
                false,
                Box::new(move || now),
            )
            .unwrap(),
        )
    }

    pub fn card_for(engine: &Engine, agent: &Keypair, version: u64, traits: &[&str], now: u64) -> Card {
        let mut c = Card {
            agent_id: AgentId::from_pubkey(&agent.public()),
            agent_pubkey: agent.public(),
            version,
            endpoints: vec![],
            traits: traits.iter().map(|s| s.to_string()).collect(),
            filters: Filters::default(),
            model: engine.model().to_string(),
            map_version: engine.map.version,
            issued_at: now,
            last_seen: now,
            expires_at: now + CARD_MAX_TTL,
            operator_cert: engine.identity.cert.clone(),
            agent_sig: Bytes64::zero(),
            node_sig: Bytes64::zero(),
        };
        c.sign_agent(agent).unwrap();
        c
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use alp_grid_core::keys::Bytes64;

    const NOW: u64 = 1_800_000_000;

    #[tokio::test]
    async fn publish_then_search_single_node() {
        let e = engine(2, NOW);
        let alice = Keypair::from_seed(&[11; 32]);
        let bob = Keypair::from_seed(&[12; 32]);
        let r = e
            .publish_card(card_for(&e, &alice, 1, &["Software developer", "Astronomy enthusiast"], NOW))
            .await
            .unwrap();
        assert_eq!(r.card_copies, 1);
        assert!(r.rejections.is_empty(), "{:?}", r.rejections);
        e.publish_card(card_for(&e, &bob, 1, &["Professional hairdresser in Paris"], NOW))
            .await
            .unwrap();
        let res = e
            .search(SearchQuery {
                text: Some("software developer".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!res.results.is_empty());
        assert_eq!(res.results[0].agent_id, AgentId::from_pubkey(&alice.public()));
        let res2 = e
            .search(SearchQuery {
                text: Some("hairdresser Paris".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(res2.results[0].agent_id, AgentId::from_pubkey(&bob.public()));
        // cached second time
        let res3 = e
            .search(SearchQuery {
                text: Some("hairdresser Paris".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(res3.cached);
        // card retrieval
        let (c, _) = e.get_card(&AgentId::from_pubkey(&alice.public())).await.unwrap();
        assert_eq!(c.unwrap().version, 1);
    }

    #[tokio::test]
    async fn new_version_replaces_old_and_revocation_hides() {
        let e = engine(2, NOW);
        let alice = Keypair::from_seed(&[11; 32]);
        e.publish_card(card_for(&e, &alice, 1, &["Plumber"], NOW)).await.unwrap();
        e.publish_card(card_for(&e, &alice, 2, &["Software developer"], NOW)).await.unwrap();
        let old = e.publish_card(card_for(&e, &alice, 1, &["Plumber"], NOW)).await.unwrap();
        assert!(!old.rejections.is_empty());
        let res = e
            .search(SearchQuery {
                text: Some("plumber".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(res.results.iter().all(|r| r.best_trait != "Plumber"));
        let rev = Revocation::new_signed(&alice, AgentId::from_pubkey(&alice.public()), RevocationTarget::Card(2), RevokedBy::Agent, NOW).unwrap();
        e.publish_revocation(rev).await.unwrap();
        let res = e
            .search(SearchQuery {
                text: Some("software developer".into()),
                at: Some(NOW + 1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(res.results.is_empty());
        let (c, r) = e.get_card(&AgentId::from_pubkey(&alice.public())).await.unwrap();
        assert!(c.is_none() && r.is_some());
    }

    #[tokio::test]
    async fn misplaced_trait_is_refused_by_guardian() {
        let e = engine(2, NOW);
        let alice = Keypair::from_seed(&[11; 32]);
        let mut card = card_for(&e, &alice, 1, &["Software developer"], NOW);
        card.countersign(&e.identity.node, NOW).unwrap();
        let v = e.embedder.embed("Software developer").unwrap();
        let real = e.map.assign(&v).unwrap().primary.zone_id;
        let wrong = (real + 1) % e.map.zones() as u32;
        let resp = e.handle(
            None,
            AtlasRequest::Store(StoreRequest::Zone {
                map_version: 1,
                zone_id: wrong,
                card,
                trait_indices: vec![0],
            }),
        );
        match resp {
            AtlasResponse::Store(s) => assert!(matches!(s.receipt.outcome, Outcome::Rejected(_))),
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn ephemeral_visible_only_in_window() {
        let e = engine(2, NOW);
        let alice = Keypair::from_seed(&[11; 32]);
        e.publish_card(card_for(&e, &alice, 1, &["Math teacher"], NOW)).await.unwrap();
        let mut eph = Ephemeral {
            agent_id: AgentId::from_pubkey(&alice.public()),
            agent_pubkey: alice.public(),
            ephemeral_id: Bytes16([1; 16]),
            text: "Math teacher available tomorrow afternoon".into(),
            filters: Filters::default(),
            valid_from: NOW + 3600,
            valid_until: NOW + 7200,
            operator_cert: e.identity.cert.clone(),
            agent_sig: Bytes64::zero(),
            node_sig: Bytes64::zero(),
        };
        eph.sign_agent(&alice).unwrap();
        let r = e.publish_ephemeral(eph).await.unwrap();
        assert!(r.zones.iter().all(|z| z.copies == 1), "{:?}", r.rejections);
        let inside = e
            .search(SearchQuery {
                text: Some("math teacher available".into()),
                at: Some(NOW + 4000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(inside.results[0].matches.iter().any(|m| matches!(m.kind, EntryKind::Ephemeral { .. })));
        let outside = e
            .search(SearchQuery {
                text: Some("math teacher available".into()),
                at: Some(NOW + 9000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(outside.results.iter().all(|r| r.matches.iter().all(|m| matches!(m.kind, EntryKind::Permanent))));
    }

    #[tokio::test]
    async fn inbox_and_vault_roundtrip() {
        let e = engine(2, NOW);
        let alice = Keypair::from_seed(&[11; 32]);
        let bob = Keypair::from_seed(&[12; 32]);
        let bob_id = AgentId::from_pubkey(&bob.public());
        let sealed = alp_grid_inbox::seal(&bob.public(), b"see you at 10").unwrap();
        let d = e.inbox_deposit(bob_id.clone(), alice.public(), sealed).await.unwrap();
        assert_eq!(d.copies, 1);
        let auth = alp_grid_inbox::sign_fetch(&bob, 5);
        let msgs = e.inbox_fetch(bob_id.clone(), bob.public(), 5, auth).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(alp_grid_inbox::open(&bob, &msgs[0].ciphertext.0).unwrap(), b"see you at 10");
        let ack = alp_grid_inbox::sign_ack(&bob, vec![msgs[0].message_id], NOW).unwrap();
        assert_eq!(e.inbox_ack(ack).await.unwrap(), 1);
        let auth = alp_grid_inbox::sign_fetch(&bob, 6);
        assert!(e.inbox_fetch(bob_id.clone(), bob.public(), 6, auth).await.unwrap().is_empty());

        let key = alp_grid_vault::VaultKey::generate();
        let enc = alp_grid_vault::encrypt(&key, &bob_id, 1, b"memory".repeat(50).as_slice()).unwrap();
        let shards = alp_grid_vault::make_shards(&bob, &e.identity.cert, 1, &enc, NOW + 1000).unwrap();
        let put = e.vault_put(shards).await.unwrap();
        assert_eq!(put.shards_stored, 30);
        let got = e.vault_get(bob_id.clone(), 1).await.unwrap();
        assert_eq!(got.shards_found, 30);
        assert_eq!(
            alp_grid_vault::decrypt(&key, &bob_id, 1, &got.encrypted.unwrap().0).unwrap(),
            b"memory".repeat(50)
        );
    }

    #[tokio::test]
    async fn receipts_are_signed_by_the_guardian() {
        let e = engine(2, NOW);
        let resp = e.handle(None, AtlasRequest::Ledger(LedgerRequest { from_seq: 0, limit: 10 }));
        let AtlasResponse::Ledger(l) = resp else { panic!() };
        assert_eq!(l.entries.len(), 1); // our own operator certificate
        l.receipt.verify().unwrap();
        assert_eq!(l.receipt.node_pubkey, e.identity.node.public());
    }
}
