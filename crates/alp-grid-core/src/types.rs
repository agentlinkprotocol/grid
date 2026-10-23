//! Signed objects of the Atlas. Field order matters: it is the canonical CBOR order.

use serde::{Deserialize, Serialize};

use crate::canon;
use crate::error::{Error, Result};
use crate::ids::AgentId;
use crate::keys::{self, Bytes16, Bytes32, Bytes64, Keypair, PublicKey};
use crate::params::domain;

/// Optional coarse filters published by the agent itself. They only pre-sort candidates.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct Filters {
    /// Geohash, precision 6 (~1 km). Matched by prefix.
    pub geohash: Option<String>,
    /// Bitmask Monday (bit 0) .. Sunday (bit 6).
    pub days: Option<u8>,
    /// ISO 639-1 codes, lowercase.
    pub langs: Vec<String>,
}

impl Filters {
    /// Does an entry with `self` match a query `q`? Absent query fields match everything.
    pub fn matches(&self, q: &Filters) -> bool {
        if let Some(qg) = &q.geohash {
            match &self.geohash {
                Some(g) if g.starts_with(qg.as_str()) || qg.starts_with(g.as_str()) => {}
                _ => return false,
            }
        }
        if let Some(qd) = q.days {
            match self.days {
                Some(d) if d & qd != 0 => {}
                _ => return false,
            }
        }
        if !q.langs.is_empty() && !q.langs.iter().any(|l| self.langs.contains(l)) {
            return false;
        }
        true
    }
}

/// A fixed-dimension vector. On the wire: `bstr` of little-endian IEEE 754 binary16.
#[derive(Clone, Debug, PartialEq)]
pub struct Vector(pub Vec<f32>);

impl Vector {
    pub fn to_f16_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * 2);
        for v in &self.0 {
            out.extend_from_slice(&half::f16::from_f32(*v).to_le_bytes());
        }
        out
    }
    pub fn from_f16_bytes(b: &[u8]) -> Result<Self> {
        if !b.len().is_multiple_of(2) {
            return Err(Error::Encoding("odd f16 byte length".into()));
        }
        Ok(Vector(
            b.as_chunks::<2>().0.iter().map(|c| half::f16::from_le_bytes([c[0], c[1]]).to_f32()).collect(),
        ))
    }
    pub fn dim(&self) -> usize {
        self.0.len()
    }
    pub fn normalize(&mut self) {
        let n: f32 = self.0.iter().map(|x| x * x).sum::<f32>().sqrt();
        if n > 0.0 {
            for x in &mut self.0 {
                *x /= n;
            }
        }
    }
    /// Cosine similarity of two L2-normalised vectors.
    pub fn dot(&self, other: &Vector) -> f32 {
        self.0.iter().zip(&other.0).map(|(a, b)| a * b).sum()
    }
}

impl Serialize for Vector {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            use serde::ser::SerializeSeq;
            let mut seq = s.serialize_seq(Some(self.0.len()))?;
            for v in &self.0 {
                seq.serialize_element(v)?;
            }
            seq.end()
        } else {
            s.serialize_bytes(&self.to_f16_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Vector {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if d.is_human_readable() {
            let v: Vec<f32> = Vec::deserialize(d)?;
            return Ok(Vector(v));
        }
        let b = serde_bytes_vec::deserialize(d)?;
        Vector::from_f16_bytes(&b).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for Vector {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ArrayBuilder::new()
            .items(utoipa::openapi::ObjectBuilder::new().schema_type(utoipa::openapi::schema::Type::Number))
            .description(Some("384-dimensional L2-normalised vector"))
            .into()
    }
}
#[cfg(feature = "openapi")]
impl utoipa::ToSchema for Vector {}

mod serde_bytes_vec {
    use serde::de;
    use std::fmt;
    pub fn deserialize<'de, D: de::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                let mut v = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    v.push(b);
                }
                Ok(v)
            }
        }
        d.deserialize_bytes(V)
    }
}

/// Opaque bytes that always encode as `bstr`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Blob(pub Vec<u8>);

impl std::fmt::Debug for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}
impl Serialize for Blob {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(&self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}
impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            return hex::decode(&s).map(Blob).map_err(serde::de::Error::custom);
        }
        Ok(Blob(serde_bytes_vec::deserialize(d)?))
    }
}
#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for Blob {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .description(Some("bytes, hex encoded"))
            .into()
    }
}
#[cfg(feature = "openapi")]
impl utoipa::ToSchema for Blob {}

// ---------------------------------------------------------------------------
// OperatorCert
// ---------------------------------------------------------------------------

/// An operator vouches for one of its nodes. Consigned to the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OperatorCert {
    pub operator_pubkey: PublicKey,
    pub node_pubkey: PublicKey,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sig: Bytes64,
}

#[derive(Serialize)]
struct OperatorCertUnsigned<'a> {
    operator_pubkey: &'a PublicKey,
    node_pubkey: &'a PublicKey,
    issued_at: u64,
    expires_at: u64,
}

impl OperatorCert {
    pub fn issue(operator: &Keypair, node_pubkey: PublicKey, issued_at: u64, expires_at: u64) -> Result<Self> {
        let operator_pubkey = operator.public();
        let h = canon::signing_hash(
            domain::OPCERT,
            &OperatorCertUnsigned {
                operator_pubkey: &operator_pubkey,
                node_pubkey: &node_pubkey,
                issued_at,
                expires_at,
            },
        )?;
        Ok(OperatorCert {
            operator_pubkey,
            node_pubkey,
            issued_at,
            expires_at,
            sig: operator.sign(&h),
        })
    }

    /// Self-signed certificate: a node that is its own operator.
    pub fn self_signed(node: &Keypair, issued_at: u64, expires_at: u64) -> Result<Self> {
        Self::issue(node, node.public(), issued_at, expires_at)
    }

    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        canon::signing_hash(
            domain::OPCERT,
            &OperatorCertUnsigned {
                operator_pubkey: &self.operator_pubkey,
                node_pubkey: &self.node_pubkey,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            },
        )
    }

    pub fn verify(&self, now: u64) -> Result<()> {
        if now >= self.expires_at || self.issued_at > now + 300 {
            return Err(Error::Expired);
        }
        keys::verify(&self.operator_pubkey, &self.signing_hash()?, &self.sig)
    }
}

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

/// The public part of an agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Card {
    pub agent_id: AgentId,
    pub agent_pubkey: PublicKey,
    /// Strictly increasing.
    pub version: u64,
    /// ALP addresses, `alp://<agent_id>@<multiaddr>` (placeholder until the ALP spec fixes it).
    pub endpoints: Vec<String>,
    /// One short sentence per trait, 1..=32 traits of at most 200 characters.
    pub traits: Vec<String>,
    pub filters: Filters,
    /// Embedding model identifier, `alp-embed-v1`.
    pub model: String,
    pub map_version: u32,
    pub issued_at: u64,
    /// Attested by the publishing node, not the agent: refreshed at every republish (24 h) and
    /// covered by `node_sig` only. Recent agents rank first.
    pub last_seen: u64,
    /// At most issued_at + 90 days.
    pub expires_at: u64,
    pub operator_cert: OperatorCert,
    pub agent_sig: Bytes64,
    pub node_sig: Bytes64,
}

#[derive(Serialize)]
struct CardUnsigned<'a> {
    agent_id: &'a AgentId,
    agent_pubkey: &'a PublicKey,
    version: u64,
    endpoints: &'a [String],
    traits: &'a [String],
    filters: &'a Filters,
    model: &'a str,
    map_version: u32,
    issued_at: u64,
    expires_at: u64,
    operator_cert: &'a OperatorCert,
}

/// What the node countersigns: the agent-signed card plus `last_seen`, which the node attests.
#[derive(Serialize)]
struct CardAgentSigned<'a> {
    agent_id: &'a AgentId,
    agent_pubkey: &'a PublicKey,
    version: u64,
    endpoints: &'a [String],
    traits: &'a [String],
    filters: &'a Filters,
    model: &'a str,
    map_version: u32,
    issued_at: u64,
    last_seen: u64,
    expires_at: u64,
    operator_cert: &'a OperatorCert,
    agent_sig: &'a Bytes64,
}

impl Card {
    fn unsigned(&self) -> CardUnsigned<'_> {
        CardUnsigned {
            agent_id: &self.agent_id,
            agent_pubkey: &self.agent_pubkey,
            version: self.version,
            endpoints: &self.endpoints,
            traits: &self.traits,
            filters: &self.filters,
            model: &self.model,
            map_version: self.map_version,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            operator_cert: &self.operator_cert,
        }
    }

    fn agent_signed(&self) -> CardAgentSigned<'_> {
        CardAgentSigned {
            agent_id: &self.agent_id,
            agent_pubkey: &self.agent_pubkey,
            version: self.version,
            endpoints: &self.endpoints,
            traits: &self.traits,
            filters: &self.filters,
            model: &self.model,
            map_version: self.map_version,
            issued_at: self.issued_at,
            last_seen: self.last_seen,
            expires_at: self.expires_at,
            operator_cert: &self.operator_cert,
            agent_sig: &self.agent_sig,
        }
    }

    /// Canonical bytes the agent signs (object without both signatures).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        canon::to_cbor(&self.unsigned())
    }

    pub fn agent_signing_hash(&self) -> Result<[u8; 32]> {
        canon::signing_hash(domain::CARD, &self.unsigned())
    }

    pub fn node_signing_hash(&self) -> Result<[u8; 32]> {
        canon::signing_hash(domain::NODE_SIG, &self.agent_signed())
    }

    /// Sign as the agent. The agent's private key never leaves the agent's process.
    pub fn sign_agent(&mut self, agent: &Keypair) -> Result<()> {
        self.agent_pubkey = agent.public();
        self.agent_id = AgentId::from_pubkey(&self.agent_pubkey);
        self.agent_sig = agent.sign(&self.agent_signing_hash()?);
        Ok(())
    }

    /// Countersign as the publishing node, attesting `last_seen = now`.
    pub fn countersign(&mut self, node: &Keypair, now: u64) -> Result<()> {
        if node.public() != self.operator_cert.node_pubkey {
            return Err(Error::invalid("operator_cert", "node key does not match certificate"));
        }
        self.last_seen = now.max(self.issued_at);
        self.node_sig = node.sign(&self.node_signing_hash()?);
        Ok(())
    }

    pub fn verify_agent_sig(&self) -> Result<()> {
        if !self.agent_id.matches(&self.agent_pubkey) {
            return Err(Error::invalid("agent_id", "does not match agent_pubkey"));
        }
        keys::verify(&self.agent_pubkey, &self.agent_signing_hash()?, &self.agent_sig)
    }

    pub fn verify_node_sig(&self) -> Result<()> {
        keys::verify(&self.operator_cert.node_pubkey, &self.node_signing_hash()?, &self.node_sig)
    }

    /// Hash identifying this exact card (all fields, both signatures).
    pub fn hash(&self) -> Result<Bytes32> {
        Ok(Bytes32(canon::hash(&canon::to_cbor(self)?)))
    }
}

// ---------------------------------------------------------------------------
// Ephemeral
// ---------------------------------------------------------------------------

/// A short-lived availability announcement. Never cached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Ephemeral {
    pub agent_id: AgentId,
    pub agent_pubkey: PublicKey,
    pub ephemeral_id: Bytes16,
    pub text: String,
    pub filters: Filters,
    pub valid_from: u64,
    /// At most valid_from + 7 days.
    pub valid_until: u64,
    pub operator_cert: OperatorCert,
    pub agent_sig: Bytes64,
    pub node_sig: Bytes64,
}

#[derive(Serialize)]
struct EphemeralUnsigned<'a> {
    agent_id: &'a AgentId,
    agent_pubkey: &'a PublicKey,
    ephemeral_id: &'a Bytes16,
    text: &'a str,
    filters: &'a Filters,
    valid_from: u64,
    valid_until: u64,
    operator_cert: &'a OperatorCert,
}

#[derive(Serialize)]
struct EphemeralAgentSigned<'a> {
    agent_id: &'a AgentId,
    agent_pubkey: &'a PublicKey,
    ephemeral_id: &'a Bytes16,
    text: &'a str,
    filters: &'a Filters,
    valid_from: u64,
    valid_until: u64,
    operator_cert: &'a OperatorCert,
    agent_sig: &'a Bytes64,
}

impl Ephemeral {
    fn unsigned(&self) -> EphemeralUnsigned<'_> {
        EphemeralUnsigned {
            agent_id: &self.agent_id,
            agent_pubkey: &self.agent_pubkey,
            ephemeral_id: &self.ephemeral_id,
            text: &self.text,
            filters: &self.filters,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            operator_cert: &self.operator_cert,
        }
    }
    fn agent_signed(&self) -> EphemeralAgentSigned<'_> {
        EphemeralAgentSigned {
            agent_id: &self.agent_id,
            agent_pubkey: &self.agent_pubkey,
            ephemeral_id: &self.ephemeral_id,
            text: &self.text,
            filters: &self.filters,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            operator_cert: &self.operator_cert,
            agent_sig: &self.agent_sig,
        }
    }
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        canon::to_cbor(&self.unsigned())
    }
    pub fn agent_signing_hash(&self) -> Result<[u8; 32]> {
        canon::signing_hash(domain::EPHEMERAL, &self.unsigned())
    }
    pub fn node_signing_hash(&self) -> Result<[u8; 32]> {
        canon::signing_hash(domain::NODE_SIG, &self.agent_signed())
    }
    pub fn sign_agent(&mut self, agent: &Keypair) -> Result<()> {
        self.agent_pubkey = agent.public();
        self.agent_id = AgentId::from_pubkey(&self.agent_pubkey);
        self.agent_sig = agent.sign(&self.agent_signing_hash()?);
        Ok(())
    }
    pub fn countersign(&mut self, node: &Keypair) -> Result<()> {
        if node.public() != self.operator_cert.node_pubkey {
            return Err(Error::invalid("operator_cert", "node key does not match certificate"));
        }
        self.node_sig = node.sign(&self.node_signing_hash()?);
        Ok(())
    }
    pub fn verify_agent_sig(&self) -> Result<()> {
        if !self.agent_id.matches(&self.agent_pubkey) {
            return Err(Error::invalid("agent_id", "does not match agent_pubkey"));
        }
        keys::verify(&self.agent_pubkey, &self.agent_signing_hash()?, &self.agent_sig)
    }
    pub fn verify_node_sig(&self) -> Result<()> {
        keys::verify(&self.operator_cert.node_pubkey, &self.node_signing_hash()?, &self.node_sig)
    }
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RevocationTarget {
    /// Revoke the card at this version (and every lower one).
    Card(u64),
    /// Revoke one ephemeral announcement.
    Ephemeral(Bytes16),
}

/// Who revokes. The agent always can; the countersigning operator can, for legal reasons,
/// and that fact goes to the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RevokedBy {
    Agent,
    Operator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Revocation {
    pub agent_id: AgentId,
    pub target: RevocationTarget,
    pub issued_at: u64,
    pub by: RevokedBy,
    /// Agent public key, or operator public key, depending on `by`.
    pub signer_pubkey: PublicKey,
    pub sig: Bytes64,
}

#[derive(Serialize)]
struct RevocationUnsigned<'a> {
    agent_id: &'a AgentId,
    target: &'a RevocationTarget,
    issued_at: u64,
    by: &'a RevokedBy,
    signer_pubkey: &'a PublicKey,
}

impl Revocation {
    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        canon::signing_hash(
            domain::REVOCATION,
            &RevocationUnsigned {
                agent_id: &self.agent_id,
                target: &self.target,
                issued_at: self.issued_at,
                by: &self.by,
                signer_pubkey: &self.signer_pubkey,
            },
        )
    }
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        canon::to_cbor(&RevocationUnsigned {
            agent_id: &self.agent_id,
            target: &self.target,
            issued_at: self.issued_at,
            by: &self.by,
            signer_pubkey: &self.signer_pubkey,
        })
    }
    pub fn new_signed(signer: &Keypair, agent_id: AgentId, target: RevocationTarget, by: RevokedBy, issued_at: u64) -> Result<Self> {
        let mut r = Revocation {
            agent_id,
            target,
            issued_at,
            by,
            signer_pubkey: signer.public(),
            sig: Bytes64::zero(),
        };
        r.sig = signer.sign(&r.signing_hash()?);
        Ok(r)
    }
    /// Verify the signature only. Whether `signer_pubkey` is allowed is checked against the card
    /// in `validate::revocation_against_card`.
    pub fn verify_sig(&self) -> Result<()> {
        keys::verify(&self.signer_pubkey, &self.signing_hash()?, &self.sig)
    }
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Store,
    Search,
    Card,
    Challenge,
    Sync,
    Inbox,
    Vault,
    Ledger,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Rejected(String),
    NotFound,
}

/// Every guardian answer is a signed receipt: proof of what it did, when, for which request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Receipt {
    pub node_pubkey: PublicKey,
    /// blake3 of the canonical request bytes.
    pub request_hash: Bytes32,
    pub kind: ReceiptKind,
    pub timestamp: u64,
    pub outcome: Outcome,
    /// blake3 of the canonical response payload (hits, card, …), so the receipt binds the answer.
    pub response_hash: Bytes32,
    pub sig: Bytes64,
}

#[derive(Serialize)]
struct ReceiptUnsigned<'a> {
    node_pubkey: &'a PublicKey,
    request_hash: &'a Bytes32,
    kind: ReceiptKind,
    timestamp: u64,
    outcome: &'a Outcome,
    response_hash: &'a Bytes32,
}

impl Receipt {
    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        canon::signing_hash(
            domain::RECEIPT,
            &ReceiptUnsigned {
                node_pubkey: &self.node_pubkey,
                request_hash: &self.request_hash,
                kind: self.kind,
                timestamp: self.timestamp,
                outcome: &self.outcome,
                response_hash: &self.response_hash,
            },
        )
    }
    pub fn issue(node: &Keypair, request_hash: Bytes32, kind: ReceiptKind, timestamp: u64, outcome: Outcome, response_hash: Bytes32) -> Result<Self> {
        let mut r = Receipt {
            node_pubkey: node.public(),
            request_hash,
            kind,
            timestamp,
            outcome,
            response_hash,
            sig: Bytes64::zero(),
        };
        r.sig = node.sign(&r.signing_hash()?);
        Ok(r)
    }
    pub fn verify(&self) -> Result<()> {
        keys::verify(&self.node_pubkey, &self.signing_hash()?, &self.sig)
    }
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/// Public facts of the network. Append-only, Merkle-rooted, gossiped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LedgerEvent {
    OperatorCert(OperatorCert),
    Revocation(Revocation),
    ChallengeFailure {
        node_pubkey: PublicKey,
        round: u64,
        controller_pubkey: PublicKey,
        controller_sig: Bytes64,
    },
    MapVersion {
        map_version: u32,
        model: String,
        map_hash: Bytes32,
        signer_pubkey: PublicKey,
        sig: Bytes64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Witness {
    pub node_pubkey: PublicKey,
    pub sig: Bytes64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LedgerEntry {
    pub seq: u64,
    pub prev_hash: Bytes32,
    pub timestamp: u64,
    pub event: LedgerEvent,
    pub witnesses: Vec<Witness>,
}

#[derive(Serialize)]
struct LedgerEntryUnsigned<'a> {
    seq: u64,
    prev_hash: &'a Bytes32,
    timestamp: u64,
    event: &'a LedgerEvent,
}

impl LedgerEntry {
    /// Hash of the entry without witnesses: what witnesses sign, and what chains to the next entry.
    pub fn hash(&self) -> Result<Bytes32> {
        Ok(Bytes32(canon::signing_hash(
            domain::LEDGER,
            &LedgerEntryUnsigned {
                seq: self.seq,
                prev_hash: &self.prev_hash,
                timestamp: self.timestamp,
                event: &self.event,
            },
        )?))
    }
    pub fn witness(&mut self, node: &Keypair) -> Result<()> {
        let h = self.hash()?;
        self.witnesses.push(Witness {
            node_pubkey: node.public(),
            sig: node.sign(&h.0),
        });
        Ok(())
    }
    pub fn verify_witnesses(&self) -> Result<usize> {
        let h = self.hash()?;
        let mut ok = 0;
        for w in &self.witnesses {
            keys::verify(&w.node_pubkey, &h.0, &w.sig)?;
            ok += 1;
        }
        Ok(ok)
    }
}

// ---------------------------------------------------------------------------
// Zone entries (what guardians index)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Permanent,
    Ephemeral { ephemeral_id: Bytes16, valid_from: u64, valid_until: u64 },
}

/// One trait of one agent inside one zone. The vector is never received: the guardian computes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ZoneEntry {
    pub agent_id: AgentId,
    pub card_version: u64,
    pub trait_index: u8,
    pub text: String,
    pub filters: Filters,
    pub last_seen: u64,
    pub expires_at: u64,
    pub kind: EntryKind,
}

impl ZoneEntry {
    pub fn from_card(card: &Card, trait_index: u8) -> Option<Self> {
        let text = card.traits.get(trait_index as usize)?.clone();
        Some(ZoneEntry {
            agent_id: card.agent_id.clone(),
            card_version: card.version,
            trait_index,
            text,
            filters: card.filters.clone(),
            last_seen: card.last_seen,
            expires_at: card.expires_at,
            kind: EntryKind::Permanent,
        })
    }

    pub fn from_ephemeral(e: &Ephemeral, card_version: u64) -> Self {
        ZoneEntry {
            agent_id: e.agent_id.clone(),
            card_version,
            trait_index: 255,
            text: e.text.clone(),
            filters: e.filters.clone(),
            last_seen: e.valid_from,
            expires_at: e.valid_until,
            kind: EntryKind::Ephemeral {
                ephemeral_id: e.ephemeral_id,
                valid_from: e.valid_from,
                valid_until: e.valid_until,
            },
        }
    }

    pub fn is_ephemeral(&self) -> bool {
        matches!(self.kind, EntryKind::Ephemeral { .. })
    }

    /// Stable key inside a zone store.
    pub fn key(&self) -> Vec<u8> {
        let mut k = self.agent_id.as_str().as_bytes().to_vec();
        k.push(0);
        match &self.kind {
            EntryKind::Permanent => {
                k.push(0);
                k.push(self.trait_index);
            }
            EntryKind::Ephemeral { ephemeral_id, .. } => {
                k.push(1);
                k.extend_from_slice(&ephemeral_id.0);
            }
        }
        k
    }
}
