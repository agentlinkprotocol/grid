//! Validation shared by publishers (before countersigning) and guardians (before storing).
//! Structural checks first (cheap), signatures last.

use crate::error::{Error, Result};
use crate::params::*;
use crate::types::*;

const GEOHASH_ALPHABET: &str = "0123456789bcdefghjkmnpqrstuvwxyz";

pub fn filters(f: &Filters) -> Result<()> {
    if let Some(g) = &f.geohash {
        if g.is_empty() || g.len() > 12 || !g.chars().all(|c| GEOHASH_ALPHABET.contains(c)) {
            return Err(Error::invalid("filters.geohash", "must be 1..=12 geohash characters"));
        }
    }
    if let Some(d) = f.days {
        if d == 0 || d > 0b0111_1111 {
            return Err(Error::invalid("filters.days", "bitmask must use bits 0..=6 and not be empty"));
        }
    }
    if f.langs.len() > LANGS_MAX {
        return Err(Error::invalid("filters.langs", "too many languages"));
    }
    for l in &f.langs {
        if l.len() != 2 || !l.chars().all(|c| c.is_ascii_lowercase()) {
            return Err(Error::invalid("filters.langs", format!("'{l}' is not an ISO 639-1 code")));
        }
    }
    Ok(())
}

fn trait_text(field: &'static str, t: &str) -> Result<()> {
    let n = t.chars().count();
    if n == 0 || n > TRAIT_MAX_CHARS {
        return Err(Error::invalid(field, format!("must be 1..={TRAIT_MAX_CHARS} characters")));
    }
    if t.chars().any(|c| c.is_control()) {
        return Err(Error::invalid(field, "control characters are not allowed"));
    }
    if t.trim() != t {
        return Err(Error::invalid(field, "leading or trailing whitespace"));
    }
    Ok(())
}

/// Structural + cryptographic validation of a card. `now` lets guardians reject clock games.
pub fn card(c: &Card, now: u64, model: &str) -> Result<()> {
    card_structure(c, now, model)?;
    c.operator_cert.verify(now)?;
    c.verify_agent_sig()?;
    c.verify_node_sig()?;
    Ok(())
}

/// Everything except the node countersignature (what a publisher checks before countersigning).
pub fn card_before_countersign(c: &Card, now: u64, model: &str) -> Result<()> {
    card_structure(c, now, model)?;
    c.operator_cert.verify(now)?;
    c.verify_agent_sig()
}

pub fn card_structure(c: &Card, now: u64, model: &str) -> Result<()> {
    if c.traits.len() < TRAITS_MIN || c.traits.len() > TRAITS_MAX {
        return Err(Error::invalid("traits", format!("must have {TRAITS_MIN}..={TRAITS_MAX} traits")));
    }
    for t in &c.traits {
        trait_text("traits", t)?;
    }
    if c.endpoints.len() > ENDPOINTS_MAX {
        return Err(Error::invalid("endpoints", "too many endpoints"));
    }
    for e in &c.endpoints {
        if e.len() > ENDPOINT_MAX_CHARS || !e.starts_with("alp://") {
            return Err(Error::invalid("endpoints", "must be alp:// addresses"));
        }
    }
    if c.model != model {
        return Err(Error::invalid("model", format!("card uses model '{}', this network runs '{model}'", c.model)));
    }
    filters(&c.filters)?;
    if c.version == 0 {
        return Err(Error::invalid("version", "must be >= 1"));
    }
    if c.issued_at > now + 300 {
        return Err(Error::invalid("issued_at", "in the future"));
    }
    if c.last_seen < c.issued_at || c.last_seen > now + 300 {
        return Err(Error::invalid("last_seen", "must be between issued_at and now"));
    }
    if c.expires_at <= now {
        return Err(Error::Expired);
    }
    if c.expires_at > c.issued_at + CARD_MAX_TTL {
        return Err(Error::invalid("expires_at", "more than 90 days after issued_at"));
    }
    Ok(())
}

pub fn ephemeral(e: &Ephemeral, now: u64) -> Result<()> {
    trait_text("text", &e.text)?;
    filters(&e.filters)?;
    if e.valid_until <= e.valid_from {
        return Err(Error::invalid("valid_until", "must be after valid_from"));
    }
    if e.valid_until - e.valid_from > EPHEMERAL_MAX_TTL {
        return Err(Error::invalid("valid_until", "more than 7 days after valid_from"));
    }
    if e.valid_until <= now {
        return Err(Error::Expired);
    }
    e.operator_cert.verify(now)?;
    e.verify_agent_sig()?;
    e.verify_node_sig()?;
    Ok(())
}

pub fn ephemeral_before_countersign(e: &Ephemeral, now: u64) -> Result<()> {
    trait_text("text", &e.text)?;
    filters(&e.filters)?;
    if e.valid_until <= e.valid_from || e.valid_until - e.valid_from > EPHEMERAL_MAX_TTL || e.valid_until <= now {
        return Err(Error::invalid("valid_until", "bad validity window"));
    }
    e.operator_cert.verify(now)?;
    e.verify_agent_sig()
}

/// A revocation is valid against a known card when its signer is that card's agent,
/// or that card's countersigning operator.
pub fn revocation_against_card(r: &Revocation, card: &Card) -> Result<()> {
    if r.agent_id != card.agent_id {
        return Err(Error::invalid("agent_id", "revocation does not target this card"));
    }
    match r.by {
        RevokedBy::Agent if r.signer_pubkey == card.agent_pubkey => {}
        RevokedBy::Operator if r.signer_pubkey == card.operator_cert.operator_pubkey => {}
        _ => return Err(Error::Signature("revocation signer is neither the agent nor the operator")),
    }
    r.verify_sig()
}

/// Without a card at hand, an agent revocation can still be checked against its own id.
pub fn revocation_standalone(r: &Revocation) -> Result<()> {
    if r.by == RevokedBy::Agent && !r.agent_id.matches(&r.signer_pubkey) {
        return Err(Error::Signature("signer is not the agent"));
    }
    r.verify_sig()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::AgentId;
    use crate::keys::{Bytes32, Bytes64, Keypair};
    use crate::time::DAY;

    pub fn sample_card(now: u64) -> (Card, Keypair, Keypair, Keypair) {
        let agent = Keypair::from_seed(&[1u8; 32]);
        let node = Keypair::from_seed(&[2u8; 32]);
        let operator = Keypair::from_seed(&[3u8; 32]);
        let cert = OperatorCert::issue(&operator, node.public(), now - DAY, now + 365 * DAY).unwrap();
        let mut card = Card {
            agent_id: AgentId::from_pubkey(&agent.public()),
            agent_pubkey: agent.public(),
            version: 1,
            endpoints: vec![format!("alp://{}@/dns4/example.org/udp/4001/quic-v1", AgentId::from_pubkey(&agent.public()))],
            traits: vec!["Software developer".into(), "Astronomy enthusiast".into()],
            filters: Filters {
                geohash: Some("u09tvw".into()),
                days: Some(0b0011111),
                langs: vec!["fr".into(), "en".into()],
            },
            model: MODEL_V1.into(),
            map_version: 1,
            issued_at: now,
            last_seen: now,
            expires_at: now + CARD_MAX_TTL,
            operator_cert: cert,
            agent_sig: Bytes64::zero(),
            node_sig: Bytes64::zero(),
        };
        card.sign_agent(&agent).unwrap();
        card.countersign(&node, now).unwrap();
        (card, agent, node, operator)
    }

    #[test]
    fn valid_card_passes() {
        let now = 1_800_000_000;
        let (c, ..) = sample_card(now);
        card_structure(&c, now, MODEL_V1).unwrap();
        card(&c, now, MODEL_V1).unwrap();
    }

    #[test]
    fn tampered_trait_fails() {
        let now = 1_800_000_000;
        let (mut c, ..) = sample_card(now);
        c.traits[0] = "Plumber".into();
        assert!(matches!(card(&c, now, MODEL_V1), Err(Error::Signature(_))));
    }

    #[test]
    fn tampered_agent_sig_breaks_node_sig() {
        let now = 1_800_000_000;
        let (mut c, agent, ..) = sample_card(now);
        c.version = 2;
        c.sign_agent(&agent).unwrap();
        assert!(c.verify_agent_sig().is_ok());
        assert!(c.verify_node_sig().is_err());
    }

    #[test]
    fn ttl_limits() {
        let now = 1_800_000_000;
        let (mut c, agent, node, ..) = sample_card(now);
        c.expires_at = now + CARD_MAX_TTL + 1;
        c.sign_agent(&agent).unwrap();
        c.countersign(&node, now).unwrap();
        assert!(card(&c, now, MODEL_V1).is_err());
    }

    #[test]
    fn revocations() {
        let now = 1_800_000_000;
        let (c, agent, _node, operator) = sample_card(now);
        let r = Revocation::new_signed(&agent, c.agent_id.clone(), RevocationTarget::Card(1), RevokedBy::Agent, now).unwrap();
        revocation_against_card(&r, &c).unwrap();
        revocation_standalone(&r).unwrap();
        let r2 = Revocation::new_signed(&operator, c.agent_id.clone(), RevocationTarget::Card(1), RevokedBy::Operator, now).unwrap();
        revocation_against_card(&r2, &c).unwrap();
        let stranger = Keypair::from_seed(&[9u8; 32]);
        let r3 = Revocation::new_signed(&stranger, c.agent_id.clone(), RevocationTarget::Card(1), RevokedBy::Operator, now).unwrap();
        assert!(revocation_against_card(&r3, &c).is_err());
    }

    #[test]
    fn filters_match() {
        let f = Filters {
            geohash: Some("u09tvw".into()),
            days: Some(0b0000011),
            langs: vec!["fr".into()],
        };
        assert!(f.matches(&Filters::default()));
        assert!(f.matches(&Filters {
            geohash: Some("u09t".into()),
            ..Default::default()
        }));
        assert!(!f.matches(&Filters {
            geohash: Some("u09x".into()),
            ..Default::default()
        }));
        assert!(f.matches(&Filters {
            days: Some(0b0000010),
            ..Default::default()
        }));
        assert!(!f.matches(&Filters {
            days: Some(0b1000000),
            ..Default::default()
        }));
        assert!(!f.matches(&Filters {
            langs: vec!["de".into()],
            ..Default::default()
        }));
    }

    #[test]
    fn cbor_roundtrip_and_bytes_are_bstr() {
        let now = 1_800_000_000;
        let (c, ..) = sample_card(now);
        let bytes = crate::canon::to_cbor(&c).unwrap();
        let back: Card = crate::canon::from_cbor(&bytes).unwrap();
        assert_eq!(c, back);
        // a 64-byte bstr header is 0x58 0x40; an array of 64 ints would be 0x98 0x40
        let needle = [0x58u8, 0x40];
        assert!(bytes.windows(2).any(|w| w == needle));
        assert!(!bytes.windows(2).any(|w| w == [0x98u8, 0x40]));
    }

    #[test]
    fn receipts_and_ledger() {
        let node = Keypair::from_seed(&[2u8; 32]);
        let r = Receipt::issue(&node, Bytes32([1; 32]), ReceiptKind::Search, 1, Outcome::Ok, Bytes32([2; 32])).unwrap();
        r.verify().unwrap();
        let mut e = LedgerEntry {
            seq: 0,
            prev_hash: Bytes32::zero(),
            timestamp: 1,
            event: LedgerEvent::ChallengeFailure {
                node_pubkey: node.public(),
                round: 7,
                controller_pubkey: node.public(),
                controller_sig: Bytes64::zero(),
            },
            witnesses: vec![],
        };
        e.witness(&node).unwrap();
        assert_eq!(e.verify_witnesses().unwrap(), 1);
        let bytes = crate::canon::to_cbor(&e).unwrap();
        let back: LedgerEntry = crate::canon::from_cbor(&bytes).unwrap();
        assert_eq!(e, back);
    }
}
