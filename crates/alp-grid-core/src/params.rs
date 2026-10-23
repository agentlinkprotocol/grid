//! Network parameters, v1. Changing any of these is a protocol change.

use crate::time::DAY;

/// Embedding dimension of `alp-embed-v1`.
pub const DIM: usize = 384;
/// Identifier of the reference embedding model.
pub const MODEL_V1: &str = "alp-embed-v1";
/// Coarse × fine centroids of the v1 map.
pub const MAP_COARSE: usize = 256;
pub const MAP_FINE: usize = 256;
pub const MAP_ZONES: usize = MAP_COARSE * MAP_FINE;
/// Second-zone threshold: publish in zone 2 when sim2 >= sim1 - this.
pub const SECOND_ZONE_MARGIN: f32 = 0.02;

pub const REPLICATION: usize = 20;
pub const KAD_K: usize = 20;
pub const KAD_ALPHA: usize = 3;
pub const NPROBE: usize = 4;
pub const DECOY_ZONES: usize = 2;
pub const GUARDIANS_PER_ZONE_QUERIED: usize = 3;
pub const SEARCH_HEDGE_MS: u64 = 150;
pub const SEARCH_TIMEOUT_MS: u64 = 600;
pub const SEARCH_MAX_K: u16 = 100;
pub const SEARCH_CACHE_SECS: u64 = 300;
pub const EXACT_SEARCH_MAX_ENTRIES: usize = 20_000;

pub const CARD_MAX_TTL: u64 = 90 * DAY;
pub const CARD_REPUBLISH: u64 = DAY;
pub const EPHEMERAL_MAX_TTL: u64 = 7 * DAY;
pub const EPHEMERAL_MAX_ACTIVE: usize = 10;
pub const INBOX_TTL: u64 = 30 * DAY;
pub const INBOX_MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const INBOX_MAX_PENDING_PER_PAIR: usize = 100;
pub const VAULT_TTL: u64 = 365 * DAY;
pub const VAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const VAULT_SHARDS: usize = 30;
pub const VAULT_DATA_SHARDS: usize = 10;
pub const RECEIPT_RETENTION: u64 = 30 * DAY;

pub const TRAITS_MIN: usize = 1;
pub const TRAITS_MAX: usize = 32;
pub const TRAIT_MAX_CHARS: usize = 200;
pub const ENDPOINTS_MAX: usize = 8;
pub const ENDPOINT_MAX_CHARS: usize = 512;
pub const LANGS_MAX: usize = 16;
pub const GEOHASH_PRECISION: usize = 6;

/// Leading zero bits required by the identity proof of work. Anti-spam only.
pub const POW_BITS: u32 = 20;
pub const TRIAL_PERIOD: u64 = 30 * DAY;
pub const BASE_QUOTA_AGENTS: u64 = 10;
pub const DRAND_ROUND_SECS: u64 = 30;
pub const CHALLENGE_CONTROLLERS: usize = 3;
pub const CHALLENGE_TIMEOUT_MS: u64 = 2_000;
pub const SERVICE_DAY_MIN_SUCCESS: f32 = 0.9;
pub const SERVICE_SENIORITY_WINDOW_DAYS: u64 = 365;
pub const MAX_GUARDIANS_PER_OPERATOR: usize = 2;
pub const MAX_GUARDIANS_PER_PREFIX: usize = 2;
pub const OVERFLOW_FILL_RATIO: f32 = 0.8;
pub const MAP_DUAL_WINDOW: u64 = 90 * DAY;

/// Signing domains. Every signature covers blake3(domain || canonical_cbor(unsigned view)).
pub mod domain {
    pub const CARD: &[u8] = b"alp-card-v1";
    pub const EPHEMERAL: &[u8] = b"alp-ephemeral-v1";
    pub const REVOCATION: &[u8] = b"alp-revocation-v1";
    pub const RECEIPT: &[u8] = b"alp-receipt-v1";
    pub const OPCERT: &[u8] = b"alp-opcert-v1";
    pub const NODE_SIG: &[u8] = b"alp-node-sig-v1";
    pub const LEDGER: &[u8] = b"alp-ledger-v1";
    pub const INBOX_ACK: &[u8] = b"alp-inbox-ack-v1";
    pub const VAULT: &[u8] = b"alp-vault-v1";
    pub const POW: &[u8] = b"alp-pow";
    pub const ZONE_KEY: &[u8] = b"alp-zone";
    pub const CARD_KEY: &[u8] = b"alp-card";
    pub const INBOX_KEY: &[u8] = b"alp-inbox";
    pub const VAULT_KEY: &[u8] = b"alp-vault";
    pub const CHALLENGE: &[u8] = b"alp-challenge";
}
