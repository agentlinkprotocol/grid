//! In-memory Atlas: many engines in one process, a transport that routes by XOR distance with the
//! diversity rule, simulated latency and loss. Used by the mandatory scenarios in `tests`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alp_grid_balance::Capacity;
use alp_grid_core::ids::Position;
use alp_grid_core::keys::{Keypair, PublicKey};
use alp_grid_core::params::{CARD_MAX_TTL, OVERFLOW_FILL_RATIO};
use alp_grid_core::transport::{NetPrefix, NodeRef, Transport, TransportError};
use alp_grid_core::types::{Card, Filters};
use alp_grid_core::wire::{AtlasRequest, AtlasResponse};
use alp_grid_core::{AgentId, Bytes64};
use alp_grid_embed::{Embedder, HashEmbedder};
use alp_grid_map::Map;
use alp_grid_node::engine::{Engine, Identity};
use alp_grid_store::Store;
use alp_grid_trust::{select_guardians, Candidate};
use async_trait::async_trait;
use parking_lot::RwLock;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct SimNode {
    pub engine: Arc<Engine>,
    pub node_ref: NodeRef,
    pub alive: AtomicBool,
    pub seniority_days: u32,
}

pub struct SimNet {
    nodes: RwLock<HashMap<PublicKey, Arc<SimNode>>>,
    pub latency_ms: AtomicU64,
    pub loss_permille: AtomicU64,
    pub requests: AtomicU64,
    clock: Arc<AtomicU64>,
    pub map: Arc<Map>,
}

pub struct SimTransport {
    net: Arc<SimNet>,
    me: NodeRef,
}

impl SimNet {
    /// `operators[i]` = number of nodes of operator i; prefixes are spread over `prefixes` /16s.
    pub fn build(operators: &[usize], prefixes: usize, now: u64, map: Arc<Map>, seed: u64) -> Arc<SimNet> {
        let clock = Arc::new(AtomicU64::new(now));
        let net = Arc::new(SimNet {
            nodes: RwLock::new(HashMap::new()),
            latency_ms: AtomicU64::new(0),
            loss_permille: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            clock,
            map,
        });
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut idx = 0u32;
        for (op_i, count) in operators.iter().enumerate() {
            let op_seed = {
                let mut s = [0u8; 32];
                s[..4].copy_from_slice(&(0xA000_0000u32 + op_i as u32).to_be_bytes());
                s
            };
            let operator = Keypair::from_seed(&op_seed);
            for _ in 0..*count {
                idx += 1;
                let mut s = [0u8; 32];
                s[..4].copy_from_slice(&idx.to_be_bytes());
                s[4..8].copy_from_slice(&(seed as u32).to_be_bytes());
                let node = Keypair::from_seed(&s);
                let prefix = NetPrefix(vec![10, rng.gen_range(0..prefixes) as u8]);
                net.add_node(node, &operator, prefix, now, 0);
            }
        }
        net
    }

    pub fn add_node(self: &Arc<Self>, node: Keypair, operator: &Keypair, prefix: NetPrefix, now: u64, seniority_days: u32) -> Arc<SimNode> {
        let cert = alp_grid_core::types::OperatorCert::issue(operator, node.public(), now.saturating_sub(60), now + 365 * 86_400).unwrap();
        let identity = Identity {
            node: node.clone(),
            operator: operator.clone(),
            cert,
            pow_nonce: 0,
            prefix: prefix.clone(),
        };
        let store = Arc::new(Store::open_temp().expect("temp store"));
        let embedder: Arc<dyn Embedder> = Arc::new(HashEmbedder::new());
        let clock = self.clock.clone();
        let engine = Arc::new(
            Engine::with_clock(
                identity,
                store,
                self.map.clone(),
                embedder,
                Capacity {
                    declared_bytes: 1 << 34,
                    used_bytes: 0,
                },
                false,
                Box::new(move || clock.load(Ordering::Relaxed)),
            )
            .expect("engine"),
        );
        // 64-zone dev maps need a wider probe than the 65 536-zone production map
        engine
            .nprobe
            .store((self.map.zones() / 4).clamp(alp_grid_core::params::NPROBE, 16), Ordering::Relaxed);
        let node_ref = NodeRef {
            pubkey: node.public(),
            operator: operator.public(),
            prefix,
        };
        engine.set_transport(Arc::new(SimTransport {
            net: self.clone(),
            me: node_ref.clone(),
        }));
        let sim = Arc::new(SimNode {
            engine,
            node_ref,
            alive: AtomicBool::new(true),
            seniority_days,
        });
        self.nodes.write().insert(node.public(), sim.clone());
        sim
    }

    pub fn now(&self) -> u64 {
        self.clock.load(Ordering::Relaxed)
    }
    pub fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs, Ordering::Relaxed);
    }
    pub fn nodes(&self) -> Vec<Arc<SimNode>> {
        let mut v: Vec<Arc<SimNode>> = self.nodes.read().values().cloned().collect();
        v.sort_by_key(|n| n.node_ref.pubkey);
        v
    }
    pub fn alive(&self) -> Vec<Arc<SimNode>> {
        self.nodes().into_iter().filter(|n| n.alive.load(Ordering::Relaxed)).collect()
    }
    pub fn kill(&self, pubkey: &PublicKey) {
        if let Some(n) = self.nodes.read().get(pubkey) {
            n.alive.store(false, Ordering::Relaxed);
        }
    }
    pub fn revive(&self, pubkey: &PublicKey) {
        if let Some(n) = self.nodes.read().get(pubkey) {
            n.alive.store(true, Ordering::Relaxed);
        }
    }
    pub fn get(&self, pubkey: &PublicKey) -> Option<Arc<SimNode>> {
        self.nodes.read().get(pubkey).cloned()
    }

    fn candidates(&self) -> Vec<Candidate> {
        self.alive()
            .iter()
            .map(|n| Candidate {
                pubkey: n.node_ref.pubkey,
                operator: n.node_ref.operator,
                prefix: alp_grid_trust::NetPrefix(n.node_ref.prefix.0.clone()),
                seniority: n.seniority_days,
                fill: n.engine.capacity.read().fill(),
            })
            .collect()
    }

    /// Guardians of a key as the network sees it (closest alive nodes, diversity applied).
    pub fn guardians(&self, key: &Position, k: usize) -> Vec<NodeRef> {
        let cands = self.candidates();
        select_guardians(key, &cands, k, OVERFLOW_FILL_RATIO)
            .into_iter()
            .map(|c| NodeRef {
                pubkey: c.pubkey,
                operator: c.operator,
                prefix: NetPrefix(c.prefix.0),
            })
            .collect()
    }

    /// Run one maintenance pass (sync + expiry) on every alive node.
    pub async fn maintenance(&self) -> usize {
        let mut n = 0;
        for node in self.alive() {
            n += node.engine.sync_round().await;
            node.engine.expire_tick();
        }
        n
    }
}

#[async_trait]
impl Transport for SimTransport {
    fn me(&self) -> NodeRef {
        self.me.clone()
    }
    async fn closest(&self, key: &Position, k: usize) -> Vec<NodeRef> {
        self.net.guardians(key, k)
    }
    fn known(&self) -> Vec<NodeRef> {
        self.net
            .alive()
            .into_iter()
            .map(|n| n.node_ref.clone())
            .filter(|n| n.pubkey != self.me.pubkey)
            .collect()
    }
    async fn request(&self, to: &NodeRef, req: AtlasRequest) -> Result<AtlasResponse, TransportError> {
        self.net.requests.fetch_add(1, Ordering::Relaxed);
        let target = self.net.get(&to.pubkey).ok_or_else(|| TransportError::Unreachable("unknown node".into()))?;
        if !target.alive.load(Ordering::Relaxed) {
            return Err(TransportError::Unreachable("node is down".into()));
        }
        let latency = self.net.latency_ms.load(Ordering::Relaxed);
        if latency > 0 {
            tokio::time::sleep(Duration::from_millis(latency)).await;
        }
        let loss = self.net.loss_permille.load(Ordering::Relaxed);
        if loss > 0 {
            let r = rand::thread_rng().gen_range(0..1000);
            if r < loss {
                return Err(TransportError::Timeout);
            }
        }
        let engine = target.engine.clone();
        let from = self.me.clone();
        let resp = tokio::task::spawn_blocking(move || engine.handle(Some(from), req))
            .await
            .map_err(|e| TransportError::Protocol(e.to_string()))?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Helpers for scenarios
// ---------------------------------------------------------------------------

pub fn agent_card(engine: &Engine, agent: &Keypair, version: u64, traits: &[String], now: u64) -> Card {
    let mut c = Card {
        agent_id: AgentId::from_pubkey(&agent.public()),
        agent_pubkey: agent.public(),
        version,
        endpoints: vec![],
        traits: traits.to_vec(),
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

/// A small synthetic corpus of profile sentences (same spirit as grid-mapbuild).
pub fn corpus(rng: &mut ChaCha20Rng, n: usize) -> Vec<String> {
    const JOBS: &[&str] = &[
        "software developer",
        "hairdresser",
        "plumber",
        "math teacher",
        "nurse",
        "architect",
        "baker",
        "lawyer",
        "photographer",
        "electrician",
        "graphic designer",
        "accountant",
        "chef",
        "dentist",
        "gardener",
        "translator",
        "mechanic",
        "yoga instructor",
        "real estate agent",
        "data scientist",
        "développeur",
        "coiffeur",
        "plombier",
        "professeur de maths",
        "boulanger",
        "avocat",
    ];
    const HOBBIES: &[&str] = &[
        "astronomy",
        "hiking",
        "chess",
        "jazz piano",
        "sailing",
        "pottery",
        "marathon running",
        "birdwatching",
        "board games",
        "climbing",
        "astronomie",
        "randonnée",
        "échecs",
    ];
    const PLACES: &[&str] = &["Paris", "Lyon", "Berlin", "Madrid", "London", "Montréal", "République", "Belleville"];
    (0..n)
        .map(|_| match rng.gen_range(0..5) {
            0 => JOBS[rng.gen_range(0..JOBS.len())].to_string(),
            1 => format!(
                "{} passionate about {}",
                JOBS[rng.gen_range(0..JOBS.len())],
                HOBBIES[rng.gen_range(0..HOBBIES.len())]
            ),
            2 => format!("{} in {}", JOBS[rng.gen_range(0..JOBS.len())], PLACES[rng.gen_range(0..PLACES.len())]),
            3 => format!("{} enthusiast", HOBBIES[rng.gen_range(0..HOBBIES.len())]),
            _ => format!(
                "Experienced {} near {}",
                JOBS[rng.gen_range(0..JOBS.len())],
                PLACES[rng.gen_range(0..PLACES.len())]
            ),
        })
        .collect()
}

/// Build a data-driven dev map from a corpus so that zones follow the data.
pub fn map_from_corpus(sentences: &[String], coarse: usize, fine: usize, seed: u64) -> Map {
    let e = HashEmbedder::new();
    let refs: Vec<&str> = sentences.iter().map(|s| s.as_str()).collect();
    let pts: Vec<Vec<f32>> = e.embed_batch(&refs).unwrap().into_iter().map(|v| v.0).collect();
    Map::build(1, &pts, coarse, fine, 8, seed).unwrap()
}

/// Exact best score per agent for a query (brute force over every entry).
pub fn exact_scores(query: &str, entries: &[(AgentId, String)]) -> HashMap<AgentId, f32> {
    let e = HashEmbedder::new();
    let q = e.embed(query).unwrap();
    let refs: Vec<&str> = entries.iter().map(|(_, t)| t.as_str()).collect();
    let vs = e.embed_batch(&refs).unwrap();
    let mut best: HashMap<AgentId, f32> = HashMap::new();
    for ((a, _), v) in entries.iter().zip(&vs) {
        let s = q.dot(v);
        let b = best.entry(a.clone()).or_insert(f32::MIN);
        if s > *b {
            *b = s;
        }
    }
    best
}

/// Recall@k with ties: a returned agent counts when its exact score reaches the k-th best exact score.
pub fn recall_at_k(query: &str, entries: &[(AgentId, String)], returned: &[AgentId], k: usize) -> f32 {
    let scores = exact_scores(query, entries);
    let mut sorted: Vec<f32> = scores.values().cloned().collect();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    let k = k.min(sorted.len());
    if k == 0 {
        return 1.0;
    }
    let threshold = sorted[k - 1] - 1e-4;
    let hits = returned
        .iter()
        .take(k)
        .filter(|a| scores.get(*a).map(|s| *s >= threshold).unwrap_or(false))
        .count();
    hits as f32 / k as f32
}

/// Exact global top-k over a set of (agent, text) pairs, for recall measurement.
pub fn exact_topk(query: &str, entries: &[(AgentId, String)], k: usize) -> Vec<AgentId> {
    let e = HashEmbedder::new();
    let q = e.embed(query).unwrap();
    let refs: Vec<&str> = entries.iter().map(|(_, t)| t.as_str()).collect();
    let vs = e.embed_batch(&refs).unwrap();
    let mut scored: Vec<(f32, &AgentId)> = entries.iter().zip(&vs).map(|((a, _), v)| (q.dot(v), a)).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    let mut out = Vec::new();
    for (_, a) in scored {
        if !out.contains(a) {
            out.push(a.clone());
        }
        if out.len() >= k {
            break;
        }
    }
    out
}
