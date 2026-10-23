//! Sealed messages for offline agents. The sender seals to the recipient's key (X25519 derived
//! from its Ed25519 key); guardians keep ciphertext only, up to 30 days, until a signed ack.
//!
//! Sealed box layout: `eph_pub(32) || nonce(24) || xchacha20poly1305(ct)`,
//! key = blake3("alp-seal-v1" || dh || eph_pub || recipient_ed_pub).

use alp_grid_core::canon;
use alp_grid_core::ids::AgentId;
use alp_grid_core::keys::{self, Bytes16, Bytes64, Keypair, PublicKey};
use alp_grid_core::params::{domain, INBOX_MAX_MESSAGE_BYTES, INBOX_MAX_PENDING_PER_PAIR, INBOX_TTL};
use alp_grid_core::types::{Blob, OperatorCert};
use alp_grid_core::wire::{InboxAck, InboxMessage};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

#[derive(Debug, Error)]
pub enum InboxError {
    #[error("message too large: {0} bytes")]
    TooLarge(usize),
    #[error("too many pending messages from this sender")]
    TooManyPending,
    #[error("crypto failure")]
    Crypto,
    #[error(transparent)]
    Core(#[from] alp_grid_core::Error),
}

pub type Result<T> = std::result::Result<T, InboxError>;

fn recipient_x25519(ed_pub: &PublicKey) -> Result<XPublic> {
    let vk = VerifyingKey::from_bytes(&ed_pub.0).map_err(|_| InboxError::Crypto)?;
    Ok(XPublic::from(vk.to_montgomery().to_bytes()))
}

fn my_x25519(ed: &Keypair) -> StaticSecret {
    let sk = SigningKey::from_bytes(&ed.seed());
    StaticSecret::from(sk.to_scalar_bytes())
}

fn seal_key(dh: &[u8; 32], eph_pub: &[u8; 32], recipient: &PublicKey) -> [u8; 32] {
    let mut p = dh.to_vec();
    p.extend_from_slice(eph_pub);
    p.extend_from_slice(&recipient.0);
    canon::domain_hash(b"alp-seal-v1", &p)
}

/// Seal `plaintext` to `recipient` (Ed25519 public key).
pub fn seal(recipient: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() + 32 + 24 + 16 > INBOX_MAX_MESSAGE_BYTES {
        return Err(InboxError::TooLarge(plaintext.len()));
    }
    let mut eph_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut eph_seed);
    let eph = StaticSecret::from(eph_seed);
    let eph_pub = XPublic::from(&eph);
    let dh = eph.diffie_hellman(&recipient_x25519(recipient)?);
    let key = seal_key(dh.as_bytes(), eph_pub.as_bytes(), recipient);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext).map_err(|_| InboxError::Crypto)?;
    let mut out = eph_pub.as_bytes().to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed box with the recipient's Ed25519 keypair.
pub fn open(recipient: &Keypair, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 32 + 24 + 16 {
        return Err(InboxError::Crypto);
    }
    let eph_pub: [u8; 32] = sealed[..32].try_into().unwrap();
    let nonce = &sealed[32..56];
    let ct = &sealed[56..];
    let dh = my_x25519(recipient).diffie_hellman(&XPublic::from(eph_pub));
    let key = seal_key(dh.as_bytes(), &eph_pub, &recipient.public());
    let cipher = XChaCha20Poly1305::new((&key).into());
    cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| InboxError::Crypto)
}

#[derive(Serialize)]
struct MessageUnsigned<'a> {
    to: &'a AgentId,
    from_pubkey: &'a PublicKey,
    message_id: &'a Bytes16,
    ciphertext: &'a Blob,
    deposited_at: u64,
    expires_at: u64,
    operator_cert: &'a OperatorCert,
}

pub fn message_hash(m: &InboxMessage) -> Result<[u8; 32]> {
    Ok(canon::signing_hash(
        domain::NODE_SIG,
        &MessageUnsigned {
            to: &m.to,
            from_pubkey: &m.from_pubkey,
            message_id: &m.message_id,
            ciphertext: &m.ciphertext,
            deposited_at: m.deposited_at,
            expires_at: m.expires_at,
            operator_cert: &m.operator_cert,
        },
    )?)
}

/// Build a deposit (sender side), then the depositing node countersigns it.
pub fn new_message(to: AgentId, from_pubkey: PublicKey, sealed: Vec<u8>, now: u64, cert: &OperatorCert) -> InboxMessage {
    let mut id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    InboxMessage {
        to,
        from_pubkey,
        message_id: Bytes16(id),
        ciphertext: Blob(sealed),
        deposited_at: now,
        expires_at: now + INBOX_TTL,
        operator_cert: cert.clone(),
        node_sig: Bytes64::zero(),
    }
}

pub fn countersign(m: &mut InboxMessage, node: &Keypair) -> Result<()> {
    m.node_sig = node.sign(&message_hash(m)?);
    Ok(())
}

/// Guardian-side checks. `pending_from_sender` is how many messages of this pair we already hold.
pub fn verify_message(m: &InboxMessage, now: u64, pending_from_sender: usize) -> Result<()> {
    if m.ciphertext.0.len() > INBOX_MAX_MESSAGE_BYTES {
        return Err(InboxError::TooLarge(m.ciphertext.0.len()));
    }
    if pending_from_sender >= INBOX_MAX_PENDING_PER_PAIR {
        return Err(InboxError::TooManyPending);
    }
    if m.expires_at <= now || m.expires_at > m.deposited_at + INBOX_TTL || m.deposited_at > now + 300 {
        return Err(alp_grid_core::Error::invalid("expires_at", "bad window").into());
    }
    m.operator_cert.verify(now)?;
    keys::verify(&m.operator_cert.node_pubkey, &message_hash(m)?, &m.node_sig)?;
    Ok(())
}

/// What an agent signs to fetch its mailbox.
pub fn fetch_auth_hash(agent_id: &AgentId, nonce: u64) -> [u8; 32] {
    let mut p = agent_id.as_str().as_bytes().to_vec();
    p.extend_from_slice(&nonce.to_be_bytes());
    canon::domain_hash(domain::INBOX_ACK, &p)
}

pub fn sign_fetch(agent: &Keypair, nonce: u64) -> Bytes64 {
    agent.sign(&fetch_auth_hash(&AgentId::from_pubkey(&agent.public()), nonce))
}

pub fn verify_fetch(agent_id: &AgentId, agent_pubkey: &PublicKey, nonce: u64, auth: &Bytes64) -> Result<()> {
    if !agent_id.matches(agent_pubkey) {
        return Err(alp_grid_core::Error::invalid("agent_id", "does not match key").into());
    }
    keys::verify(agent_pubkey, &fetch_auth_hash(agent_id, nonce), auth)?;
    Ok(())
}

#[derive(Serialize)]
struct AckUnsigned<'a> {
    agent_id: &'a AgentId,
    agent_pubkey: &'a PublicKey,
    message_ids: &'a [Bytes16],
    issued_at: u64,
}

pub fn ack_hash(a: &InboxAck) -> Result<[u8; 32]> {
    Ok(canon::signing_hash(
        domain::INBOX_ACK,
        &AckUnsigned {
            agent_id: &a.agent_id,
            agent_pubkey: &a.agent_pubkey,
            message_ids: &a.message_ids,
            issued_at: a.issued_at,
        },
    )?)
}

pub fn sign_ack(agent: &Keypair, message_ids: Vec<Bytes16>, now: u64) -> Result<InboxAck> {
    let mut a = InboxAck {
        agent_id: AgentId::from_pubkey(&agent.public()),
        agent_pubkey: agent.public(),
        message_ids,
        issued_at: now,
        sig: Bytes64::zero(),
    };
    a.sig = agent.sign(&ack_hash(&a)?);
    Ok(a)
}

pub fn verify_ack(a: &InboxAck) -> Result<()> {
    if !a.agent_id.matches(&a.agent_pubkey) {
        return Err(alp_grid_core::Error::invalid("agent_id", "does not match key").into());
    }
    keys::verify(&a.agent_pubkey, &ack_hash(a)?, &a.sig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_sign_flow() {
        let alice = Keypair::from_seed(&[1; 32]);
        let bob = Keypair::from_seed(&[2; 32]);
        let node = Keypair::from_seed(&[3; 32]);
        let cert = OperatorCert::self_signed(&node, 0, u64::MAX / 2).unwrap();
        let sealed = seal(&bob.public(), b"Appointment confirmed for 10:00").unwrap();
        assert_eq!(open(&bob, &sealed).unwrap(), b"Appointment confirmed for 10:00");
        assert!(open(&alice, &sealed).is_err());
        let mut m = new_message(AgentId::from_pubkey(&bob.public()), alice.public(), sealed, 1000, &cert);
        countersign(&mut m, &node).unwrap();
        verify_message(&m, 1001, 0).unwrap();
        assert!(verify_message(&m, 1001, INBOX_MAX_PENDING_PER_PAIR).is_err());
        let auth = sign_fetch(&bob, 77);
        verify_fetch(&m.to, &bob.public(), 77, &auth).unwrap();
        assert!(verify_fetch(&m.to, &bob.public(), 78, &auth).is_err());
        let ack = sign_ack(&bob, vec![m.message_id], 1002).unwrap();
        verify_ack(&ack).unwrap();
        let mut forged = ack.clone();
        forged.agent_pubkey = alice.public();
        assert!(verify_ack(&forged).is_err());
    }
}
