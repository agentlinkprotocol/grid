//! Request/response payloads of the `/alp/atlas/*` protocols. CBOR on the wire.
//! Every response carries a signed [`Receipt`].

use serde::{Deserialize, Serialize};

use crate::ids::{AgentId, Position};
use crate::keys::{Bytes16, Bytes32, Bytes64, PublicKey};
use crate::types::*;

pub const PROTOCOL_STORE: &str = "/alp/atlas/store/1";
pub const PROTOCOL_SEARCH: &str = "/alp/atlas/search/1";
pub const PROTOCOL_CARD: &str = "/alp/atlas/card/1";
pub const PROTOCOL_CHALLENGE: &str = "/alp/atlas/challenge/1";
pub const PROTOCOL_SYNC: &str = "/alp/atlas/sync/1";
pub const PROTOCOL_VAULT: &str = "/alp/atlas/vault/1";
pub const PROTOCOL_INBOX: &str = "/alp/atlas/inbox/1";
pub const PROTOCOL_LEDGER: &str = "/alp/atlas/ledger/1";

pub const ALL_PROTOCOLS: &[&str] = &[
    PROTOCOL_STORE,
    PROTOCOL_SEARCH,
    PROTOCOL_CARD,
    PROTOCOL_CHALLENGE,
    PROTOCOL_SYNC,
    PROTOCOL_VAULT,
    PROTOCOL_INBOX,
    PROTOCOL_LEDGER,
];

/// What a publisher sends to a guardian.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum StoreRequest {
    /// Full card, to the 20 guardians of card_key(agent_id).
    Card(Card),
    /// Traits of a signed card meant for one zone. The guardian recomputes the vectors
    /// and checks that each trait belongs to `zone_id` (primary or second zone).
    Zone {
        map_version: u32,
        zone_id: u32,
        card: Card,
        trait_indices: Vec<u8>,
    },
    /// An ephemeral announcement meant for one zone.
    Ephemeral {
        map_version: u32,
        zone_id: u32,
        ephemeral: Ephemeral,
    },
    Revocation(Revocation),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StoreResponse {
    pub receipt: Receipt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SearchRequest {
    pub map_version: u32,
    pub zone_id: u32,
    pub vector: Vector,
    pub filters: Filters,
    /// Target date. When set, valid ephemerals are included and the answer is never cached.
    pub at: Option<u64>,
    /// Results wanted from this zone, at most 100.
    pub k: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SearchHit {
    pub agent_id: AgentId,
    pub card_version: u64,
    pub trait_index: u8,
    pub text: String,
    pub score: f32,
    pub last_seen: u64,
    pub kind: EntryKind,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SearchResponse {
    pub hits: Vec<SearchHit>,
    pub receipt: Receipt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CardRequest {
    pub agent_id: AgentId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CardResponse {
    pub card: Option<Card>,
    pub revocation: Option<Revocation>,
    pub receipt: Receipt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    /// Prove you store this card.
    Storage { agent_id: AgentId },
    /// Prove you serve this zone: answer a search.
    Service { map_version: u32, zone_id: u32, vector: Vector },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Challenge {
    pub round: u64,
    pub target: PublicKey,
    pub kind: ChallengeKind,
    pub controller_pubkey: PublicKey,
    pub sig: Bytes64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum ChallengeProof {
    Card(Card),
    Hits(Vec<SearchHit>),
    Missing,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChallengeResponse {
    pub proof: ChallengeProof,
    pub receipt: Receipt,
}

/// Anti-entropy between guardians of one key: "here is what I have, send me what I miss".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyncRequest {
    pub key: Position,
    pub have: Vec<Bytes32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyncResponse {
    /// What the requester lacks.
    pub missing: Vec<StoreRequest>,
    /// What the responder holds, so the requester can push what the responder lacks.
    pub have: Vec<Bytes32>,
    pub receipt: Receipt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InboxRequest {
    Deposit(InboxMessage),
    /// Fetch pending messages; `auth` is the agent's signature over blake3("alp-inbox-ack-v1" || agent_id || nonce).
    Fetch {
        agent_id: AgentId,
        agent_pubkey: PublicKey,
        nonce: u64,
        auth: Bytes64,
    },
    Ack(InboxAck),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InboxMessage {
    pub to: AgentId,
    pub from_pubkey: PublicKey,
    pub message_id: Bytes16,
    /// Sealed to the recipient (X25519 + XChaCha20-Poly1305). Guardians cannot read it.
    pub ciphertext: Blob,
    pub deposited_at: u64,
    pub expires_at: u64,
    pub operator_cert: OperatorCert,
    pub node_sig: Bytes64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InboxAck {
    pub agent_id: AgentId,
    pub agent_pubkey: PublicKey,
    pub message_ids: Vec<Bytes16>,
    pub issued_at: u64,
    pub sig: Bytes64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InboxResponse {
    pub messages: Vec<InboxMessage>,
    pub receipt: Receipt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum VaultRequest {
    Put(VaultShard),
    Get { agent_id: AgentId, snapshot: u64, index: u8 },
}

/// One Reed-Solomon shard of an encrypted snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VaultShard {
    pub agent_id: AgentId,
    pub agent_pubkey: PublicKey,
    pub snapshot: u64,
    pub index: u8,
    pub total: u8,
    pub data_shards: u8,
    pub shard_hash: Bytes32,
    pub data: Blob,
    pub expires_at: u64,
    pub operator_cert: OperatorCert,
    pub agent_sig: Bytes64,
    pub node_sig: Bytes64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VaultResponse {
    pub shard: Option<VaultShard>,
    pub receipt: Receipt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LedgerRequest {
    pub from_seq: u64,
    pub limit: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LedgerResponse {
    pub entries: Vec<LedgerEntry>,
    pub root: Bytes32,
    pub size: u64,
    pub receipt: Receipt,
}

/// Single envelope used by the libp2p request-response behaviour.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum AtlasRequest {
    Store(StoreRequest),
    Search(SearchRequest),
    Card(CardRequest),
    Challenge(Challenge),
    Sync(SyncRequest),
    Inbox(InboxRequest),
    Vault(VaultRequest),
    Ledger(LedgerRequest),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum AtlasResponse {
    Store(StoreResponse),
    Search(SearchResponse),
    Card(CardResponse),
    Challenge(ChallengeResponse),
    Sync(SyncResponse),
    Inbox(InboxResponse),
    Vault(VaultResponse),
    Ledger(LedgerResponse),
    Error(String),
}

impl AtlasRequest {
    pub fn protocol(&self) -> &'static str {
        match self {
            AtlasRequest::Store(_) => PROTOCOL_STORE,
            AtlasRequest::Search(_) => PROTOCOL_SEARCH,
            AtlasRequest::Card(_) => PROTOCOL_CARD,
            AtlasRequest::Challenge(_) => PROTOCOL_CHALLENGE,
            AtlasRequest::Sync(_) => PROTOCOL_SYNC,
            AtlasRequest::Inbox(_) => PROTOCOL_INBOX,
            AtlasRequest::Vault(_) => PROTOCOL_VAULT,
            AtlasRequest::Ledger(_) => PROTOCOL_LEDGER,
        }
    }
}

impl AtlasResponse {
    pub fn receipt(&self) -> Option<&Receipt> {
        match self {
            AtlasResponse::Store(r) => Some(&r.receipt),
            AtlasResponse::Search(r) => Some(&r.receipt),
            AtlasResponse::Card(r) => Some(&r.receipt),
            AtlasResponse::Challenge(r) => Some(&r.receipt),
            AtlasResponse::Sync(r) => Some(&r.receipt),
            AtlasResponse::Inbox(r) => Some(&r.receipt),
            AtlasResponse::Vault(r) => Some(&r.receipt),
            AtlasResponse::Ledger(r) => Some(&r.receipt),
            AtlasResponse::Error(_) => None,
        }
    }
}
