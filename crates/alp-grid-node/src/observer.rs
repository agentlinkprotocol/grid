//! Observer mode: aggregate what this node sees of the Atlas, for the public Console.
//! No GeoIP in v1: operators and nodes are grouped by network prefix.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use alp_grid_core::canon;
use alp_grid_core::keys::PublicKey;
use alp_grid_core::types::LedgerEvent;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::engine::{Engine, MetricsSnapshot};

const SERIES_META: &str = "observer_series";
const SERIES_MAX: usize = 7 * 24 * 60; // 7 days of minutes

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct SeriesPoint {
    /// Unix minute.
    pub minute: u64,
    pub nodes: u64,
    pub operators: u64,
    pub searches_served: u64,
    pub zone_entries: u64,
    pub ledger_size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct OperatorStat {
    pub operator: PublicKey,
    pub nodes: u64,
    pub share: f32,
    pub seniority_days: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct PrefixStat {
    /// Hex of the /16 (IPv4) or /48 (IPv6) prefix; empty when unknown.
    pub prefix: String,
    pub nodes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ZoneStat {
    pub zone_id: u32,
    pub entries: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct LedgerSummary {
    pub seq: u64,
    pub timestamp: u64,
    pub kind: String,
    pub subject: String,
    pub witnesses: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AtlasStats {
    pub sampled_at: u64,
    pub observer: PublicKey,
    pub map_version: u32,
    pub map_zones: u64,
    pub model: String,
    pub nodes_known: u64,
    pub operators_known: u64,
    pub biggest_operator_share: f32,
    pub operators: Vec<OperatorStat>,
    pub prefixes: Vec<PrefixStat>,
    pub seniority_histogram: BTreeMap<String, u64>,
    pub zones_held: u64,
    pub zone_entries: u64,
    pub cards_held: u64,
    pub hot_zones: Vec<ZoneStat>,
    pub capacity_fill: f32,
    pub ledger_size: u64,
    pub ledger_root: String,
    pub ledger_recent: Vec<LedgerSummary>,
    pub metrics: MetricsSnapshot,
    pub series: Vec<SeriesPoint>,
}

pub fn collect(engine: &Arc<Engine>) -> AtlasStats {
    let now = engine.now();
    let known = engine.known_nodes();
    let trust = engine.trust.read();
    let mut per_op: HashMap<PublicKey, (u64, u32)> = HashMap::new();
    let mut per_prefix: HashMap<String, u64> = HashMap::new();
    let mut hist: BTreeMap<String, u64> = BTreeMap::new();
    for n in &known {
        let e = per_op.entry(n.operator).or_insert((0, 0));
        e.0 += 1;
        let s = trust.book.seniority(&n.pubkey, now);
        e.1 += s;
        *per_prefix.entry(hex::encode(&n.prefix.0)).or_insert(0) += 1;
        let bucket = match s {
            0 => "0",
            1..=7 => "1-7",
            8..=30 => "8-30",
            31..=90 => "31-90",
            91..=365 => "91-365",
            _ => "365+",
        };
        *hist.entry(bucket.to_string()).or_insert(0) += 1;
    }
    // operators from the ledger (certificates) count even when their nodes are not connected to us
    for e in engine.ledger.range(0, 10_000).unwrap_or_default() {
        if let LedgerEvent::OperatorCert(c) = e.event {
            per_op.entry(c.operator_pubkey).or_insert((0, 0));
        }
    }
    let total_nodes = known.len().max(1) as f32;
    let mut operators: Vec<OperatorStat> = per_op
        .into_iter()
        .map(|(operator, (nodes, sen))| OperatorStat {
            operator,
            nodes,
            share: nodes as f32 / total_nodes,
            seniority_days: sen,
        })
        .collect();
    operators.sort_by_key(|o| std::cmp::Reverse(o.nodes));
    let biggest = operators.first().map(|o| o.share).unwrap_or(0.0);
    let mut prefixes: Vec<PrefixStat> = per_prefix.into_iter().map(|(prefix, nodes)| PrefixStat { prefix, nodes }).collect();
    prefixes.sort_by_key(|p| std::cmp::Reverse(p.nodes));
    let zones = engine.store.zones_held();
    let mut hot: Vec<ZoneStat> = zones
        .iter()
        .map(|(z, n)| ZoneStat {
            zone_id: z.zone_id,
            entries: *n as u64,
        })
        .collect();
    hot.sort_by_key(|z| std::cmp::Reverse(z.entries));
    hot.truncate(10);
    let store = engine.store.stats().unwrap_or_default();
    let ledger_len = engine.ledger.len();
    let recent: Vec<LedgerSummary> = engine
        .ledger
        .range(ledger_len.saturating_sub(20), 20)
        .unwrap_or_default()
        .into_iter()
        .rev()
        .map(|e| {
            let (kind, subject) = match &e.event {
                LedgerEvent::OperatorCert(c) => ("operator_cert", c.operator_pubkey.to_hex()),
                LedgerEvent::Revocation(r) => ("revocation", r.agent_id.to_string()),
                LedgerEvent::ChallengeFailure { node_pubkey, .. } => ("challenge_failure", node_pubkey.to_hex()),
                LedgerEvent::MapVersion { map_version, .. } => ("map_version", map_version.to_string()),
            };
            LedgerSummary {
                seq: e.seq,
                timestamp: e.timestamp,
                kind: kind.into(),
                subject,
                witnesses: e.witnesses.len(),
            }
        })
        .collect();
    let series: Vec<SeriesPoint> = engine
        .store
        .meta_get(SERIES_META)
        .ok()
        .flatten()
        .and_then(|b| canon::from_cbor(&b).ok())
        .unwrap_or_default();
    AtlasStats {
        sampled_at: now,
        observer: engine.identity.node.public(),
        map_version: engine.map.version,
        map_zones: engine.map.zones() as u64,
        model: engine.model().to_string(),
        nodes_known: known.len() as u64,
        operators_known: operators.len() as u64,
        biggest_operator_share: biggest,
        operators: operators.into_iter().take(50).collect(),
        prefixes: prefixes.into_iter().take(50).collect(),
        seniority_histogram: hist,
        zones_held: zones.len() as u64,
        zone_entries: store.zone_entries,
        cards_held: store.cards,
        hot_zones: hot,
        capacity_fill: engine.capacity.read().fill(),
        ledger_size: ledger_len,
        ledger_root: engine.ledger.root().to_hex(),
        ledger_recent: recent,
        metrics: engine.metrics.snapshot(),
        series,
    }
}

/// Append one point to the stored time series (call once a minute).
pub fn sample(engine: &Arc<Engine>) {
    let now = engine.now();
    let stats = collect(engine);
    let served = stats.metrics.served_per_minute.iter().rev().take(1).map(|(_, c)| *c).next().unwrap_or(0);
    let mut series: Vec<SeriesPoint> = engine
        .store
        .meta_get(SERIES_META)
        .ok()
        .flatten()
        .and_then(|b| canon::from_cbor(&b).ok())
        .unwrap_or_default();
    series.push(SeriesPoint {
        minute: now / 60,
        nodes: stats.nodes_known,
        operators: stats.operators_known,
        searches_served: served,
        zone_entries: stats.zone_entries,
        ledger_size: stats.ledger_size,
    });
    if series.len() > SERIES_MAX {
        let drop = series.len() - SERIES_MAX;
        series.drain(..drop);
    }
    if let Ok(b) = canon::to_cbor(&series) {
        let _ = engine.store.meta_set(SERIES_META, &b);
    }
}
