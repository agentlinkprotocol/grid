//! Challenges drawn by common randomness. For round `r` and target `N`, the controllers are the
//! `CHALLENGE_CONTROLLERS` nodes whose position is closest to blake3("alp-challenge" || r || N).
//! Anyone can recompute who had the right to challenge.

use alp_grid_core::canon;
use alp_grid_core::ids::Position;
use alp_grid_core::keys::{self, Bytes32, Bytes64, Keypair, PublicKey};
use alp_grid_core::params::{domain, CHALLENGE_CONTROLLERS, DRAND_ROUND_SECS};
use alp_grid_core::wire::{Challenge, ChallengeKind};
use alp_grid_core::{Error, Result};
use serde::Serialize;

/// Round number from a wall clock when no drand beacon is available (dev, simulator).
pub fn local_round(now: u64) -> u64 {
    now / DRAND_ROUND_SECS
}

/// The point in the XOR space that selects the controllers of `target` at `round`.
pub fn controller_point(round: u64, target: &PublicKey) -> Position {
    let mut payload = round.to_be_bytes().to_vec();
    payload.extend_from_slice(&target.0);
    Position(Bytes32(canon::domain_hash(domain::CHALLENGE, &payload)))
}

/// Controllers of `target` at `round`, among `candidates` (the target itself excluded).
pub fn controllers_for(round: u64, target: &PublicKey, candidates: &[PublicKey]) -> Vec<PublicKey> {
    let point = controller_point(round, target);
    let mut ranked: Vec<([u8; 32], PublicKey)> = candidates
        .iter()
        .filter(|c| *c != target)
        .map(|c| (Position::of_node(c).distance(&point), *c))
        .collect();
    ranked.sort();
    ranked.into_iter().take(CHALLENGE_CONTROLLERS).map(|(_, c)| c).collect()
}

pub fn is_controller(round: u64, target: &PublicKey, controller: &PublicKey, candidates: &[PublicKey]) -> bool {
    controllers_for(round, target, candidates).contains(controller)
}

#[derive(Serialize)]
struct ChallengeUnsigned<'a> {
    round: u64,
    target: &'a PublicKey,
    kind: &'a ChallengeKind,
    controller_pubkey: &'a PublicKey,
}

pub fn challenge_hash(c: &Challenge) -> Result<[u8; 32]> {
    canon::signing_hash(
        domain::CHALLENGE,
        &ChallengeUnsigned {
            round: c.round,
            target: &c.target,
            kind: &c.kind,
            controller_pubkey: &c.controller_pubkey,
        },
    )
}

pub fn sign_challenge(controller: &Keypair, round: u64, target: PublicKey, kind: ChallengeKind) -> Result<Challenge> {
    let mut c = Challenge {
        round,
        target,
        kind,
        controller_pubkey: controller.public(),
        sig: Bytes64::zero(),
    };
    c.sig = controller.sign(&challenge_hash(&c)?);
    Ok(c)
}

/// A target verifies: signature, and that the controller was entitled at that round.
pub fn verify_challenge(c: &Challenge, me: &PublicKey, candidates: &[PublicKey], current_round: u64) -> Result<()> {
    if &c.target != me {
        return Err(Error::invalid("target", "challenge is not for this node"));
    }
    if c.round + 2 < current_round || c.round > current_round + 1 {
        return Err(Error::invalid("round", "challenge round too old or in the future"));
    }
    keys::verify(&c.controller_pubkey, &challenge_hash(c)?, &c.sig)?;
    if !is_controller(c.round, me, &c.controller_pubkey, candidates) {
        return Err(Error::Signature("controller was not drawn for this round"));
    }
    Ok(())
}

/// What a controller signs when it records a failure in the ledger.
pub fn failure_hash(node: &PublicKey, round: u64) -> [u8; 32] {
    let mut payload = b"failure".to_vec();
    payload.extend_from_slice(&node.0);
    payload.extend_from_slice(&round.to_be_bytes());
    canon::domain_hash(domain::CHALLENGE, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alp_grid_core::ids::AgentId;

    fn keys(n: u8) -> Vec<Keypair> {
        (1..=n).map(|i| Keypair::from_seed(&[i; 32])).collect()
    }

    #[test]
    fn controllers_are_deterministic_and_exclude_target() {
        let ks = keys(12);
        let pks: Vec<PublicKey> = ks.iter().map(|k| k.public()).collect();
        let c1 = controllers_for(42, &pks[0], &pks);
        let c2 = controllers_for(42, &pks[0], &pks);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), CHALLENGE_CONTROLLERS);
        assert!(!c1.contains(&pks[0]));
        let c3 = controllers_for(43, &pks[0], &pks);
        assert_ne!(c1, c3);
    }

    #[test]
    fn signed_challenge_verifies_only_for_drawn_controller() {
        let ks = keys(12);
        let pks: Vec<PublicKey> = ks.iter().map(|k| k.public()).collect();
        let target = &pks[0];
        let ctrls = controllers_for(42, target, &pks);
        let ctrl_kp = ks.iter().find(|k| k.public() == ctrls[0]).unwrap();
        let kind = ChallengeKind::Storage {
            agent_id: AgentId::from_pubkey(&pks[5]),
        };
        let ch = sign_challenge(ctrl_kp, 42, *target, kind.clone()).unwrap();
        verify_challenge(&ch, target, &pks, 42).unwrap();
        let outsider = ks.iter().find(|k| !ctrls.contains(&k.public()) && &k.public() != target).unwrap();
        let bad = sign_challenge(outsider, 42, *target, kind).unwrap();
        assert!(verify_challenge(&bad, target, &pks, 42).is_err());
    }
}
