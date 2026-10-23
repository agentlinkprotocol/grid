//! Generates `test-vectors/v1.json`: canonical bytes and signatures for fixed keys and timestamps.
//! The TypeScript and Python SDKs replay this file in their test suites.

use alp_grid_core::canon;
use alp_grid_core::ids::AgentId;
use alp_grid_core::keys::{Bytes16, Bytes32, Bytes64, Keypair};
use alp_grid_core::params::{domain, CARD_MAX_TTL, MODEL_V1};
use alp_grid_core::time::DAY;
use alp_grid_core::types::*;
use serde_json::json;

fn main() {
    let now: u64 = 1_800_000_000;
    let agent = Keypair::from_seed(&[1u8; 32]);
    let node = Keypair::from_seed(&[2u8; 32]);
    let operator = Keypair::from_seed(&[3u8; 32]);

    let cert = OperatorCert::issue(&operator, node.public(), now - DAY, now + 365 * DAY).unwrap();
    let agent_id = AgentId::from_pubkey(&agent.public());

    let mut card = Card {
        agent_id: agent_id.clone(),
        agent_pubkey: agent.public(),
        version: 1,
        endpoints: vec![format!("alp://{agent_id}@/dns4/example.org/udp/4001/quic-v1")],
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
        operator_cert: cert.clone(),
        agent_sig: Bytes64::zero(),
        node_sig: Bytes64::zero(),
    };
    card.sign_agent(&agent).unwrap();
    card.countersign(&node, now).unwrap();

    let mut eph = Ephemeral {
        agent_id: agent_id.clone(),
        agent_pubkey: agent.public(),
        ephemeral_id: Bytes16([0xAB; 16]),
        text: "Available tomorrow 14:00-18:00".into(),
        filters: Filters {
            geohash: None,
            days: None,
            langs: vec![],
        },
        valid_from: now,
        valid_until: now + DAY,
        operator_cert: cert.clone(),
        agent_sig: Bytes64::zero(),
        node_sig: Bytes64::zero(),
    };
    eph.sign_agent(&agent).unwrap();
    eph.countersign(&node).unwrap();

    let rev = Revocation::new_signed(&agent, agent_id.clone(), RevocationTarget::Card(1), RevokedBy::Agent, now + 1).unwrap();
    let rev_op = Revocation::new_signed(
        &operator,
        agent_id.clone(),
        RevocationTarget::Ephemeral(Bytes16([0xAB; 16])),
        RevokedBy::Operator,
        now + 2,
    )
    .unwrap();

    let receipt = Receipt::issue(&node, Bytes32([0x11; 32]), ReceiptKind::Search, now, Outcome::Ok, Bytes32([0x22; 32])).unwrap();
    let receipt_rej = Receipt::issue(
        &node,
        Bytes32([0x11; 32]),
        ReceiptKind::Store,
        now,
        Outcome::Rejected("quota".into()),
        Bytes32::zero(),
    )
    .unwrap();

    let out = json!({
        "version": 1,
        "description": "Canonical CBOR and Ed25519 test vectors for the Atlas v1 signed objects. Keys are Ed25519 seeds.",
        "keys": {
            "agent_seed": hex::encode([1u8; 32]), "agent_pubkey": agent.public().to_hex(),
            "node_seed": hex::encode([2u8; 32]), "node_pubkey": node.public().to_hex(),
            "operator_seed": hex::encode([3u8; 32]), "operator_pubkey": operator.public().to_hex(),
        },
        "agent_id": agent_id.as_str(),
        "domains": {
            "card": String::from_utf8_lossy(domain::CARD), "ephemeral": String::from_utf8_lossy(domain::EPHEMERAL),
            "revocation": String::from_utf8_lossy(domain::REVOCATION), "receipt": String::from_utf8_lossy(domain::RECEIPT),
            "opcert": String::from_utf8_lossy(domain::OPCERT), "node_sig": String::from_utf8_lossy(domain::NODE_SIG),
        },
        "operator_cert": {
            "object": { "operator_pubkey": cert.operator_pubkey.to_hex(), "node_pubkey": cert.node_pubkey.to_hex(), "issued_at": cert.issued_at, "expires_at": cert.expires_at },
            "signing_hash": hex::encode(cert.signing_hash().unwrap()),
            "sig": cert.sig.to_hex(),
            "cbor": hex::encode(canon::to_cbor(&cert).unwrap()),
        },
        "card": {
            "object": {
                "agent_id": card.agent_id.as_str(), "agent_pubkey": card.agent_pubkey.to_hex(), "version": card.version,
                "endpoints": card.endpoints, "traits": card.traits,
                "filters": { "geohash": card.filters.geohash, "days": card.filters.days, "langs": card.filters.langs },
                "model": card.model, "map_version": card.map_version, "issued_at": card.issued_at, "last_seen": card.last_seen, "expires_at": card.expires_at,
            },
            "unsigned_cbor": hex::encode(card.unsigned_bytes().unwrap()),
            "agent_signing_hash": hex::encode(card.agent_signing_hash().unwrap()),
            "agent_sig": card.agent_sig.to_hex(),
            "node_signing_hash": hex::encode(card.node_signing_hash().unwrap()),
            "node_sig": card.node_sig.to_hex(),
            "cbor": hex::encode(canon::to_cbor(&card).unwrap()),
        },
        "ephemeral": {
            "object": {
                "agent_id": eph.agent_id.as_str(), "agent_pubkey": eph.agent_pubkey.to_hex(), "ephemeral_id": eph.ephemeral_id.to_hex(),
                "text": eph.text, "filters": { "geohash": null, "days": null, "langs": [] }, "valid_from": eph.valid_from, "valid_until": eph.valid_until,
            },
            "unsigned_cbor": hex::encode(eph.unsigned_bytes().unwrap()),
            "agent_signing_hash": hex::encode(eph.agent_signing_hash().unwrap()),
            "agent_sig": eph.agent_sig.to_hex(),
            "node_sig": eph.node_sig.to_hex(),
            "cbor": hex::encode(canon::to_cbor(&eph).unwrap()),
        },
        "revocation_by_agent": {
            "object": { "agent_id": rev.agent_id.as_str(), "target": { "card": 1 }, "issued_at": rev.issued_at, "by": "agent", "signer_pubkey": rev.signer_pubkey.to_hex() },
            "unsigned_cbor": hex::encode(rev.unsigned_bytes().unwrap()),
            "signing_hash": hex::encode(rev.signing_hash().unwrap()),
            "sig": rev.sig.to_hex(),
            "cbor": hex::encode(canon::to_cbor(&rev).unwrap()),
        },
        "revocation_by_operator": {
            "object": { "agent_id": rev_op.agent_id.as_str(), "target": { "ephemeral": hex::encode([0xABu8; 16]) }, "issued_at": rev_op.issued_at, "by": "operator", "signer_pubkey": rev_op.signer_pubkey.to_hex() },
            "unsigned_cbor": hex::encode(rev_op.unsigned_bytes().unwrap()),
            "signing_hash": hex::encode(rev_op.signing_hash().unwrap()),
            "sig": rev_op.sig.to_hex(),
            "cbor": hex::encode(canon::to_cbor(&rev_op).unwrap()),
        },
        "receipt_ok": {
            "object": { "node_pubkey": receipt.node_pubkey.to_hex(), "request_hash": receipt.request_hash.to_hex(), "kind": "search", "timestamp": receipt.timestamp, "outcome": "ok", "response_hash": receipt.response_hash.to_hex() },
            "signing_hash": hex::encode(receipt.signing_hash().unwrap()),
            "sig": receipt.sig.to_hex(),
            "cbor": hex::encode(canon::to_cbor(&receipt).unwrap()),
        },
        "receipt_rejected": {
            "object": { "node_pubkey": receipt_rej.node_pubkey.to_hex(), "request_hash": receipt_rej.request_hash.to_hex(), "kind": "store", "timestamp": receipt_rej.timestamp, "outcome": { "rejected": "quota" }, "response_hash": receipt_rej.response_hash.to_hex() },
            "signing_hash": hex::encode(receipt_rej.signing_hash().unwrap()),
            "sig": receipt_rej.sig.to_hex(),
            "cbor": hex::encode(canon::to_cbor(&receipt_rej).unwrap()),
        },
    });

    let path = std::env::args().nth(1).unwrap_or_else(|| "test-vectors/v1.json".to_string());
    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    eprintln!("wrote {path}");
}
