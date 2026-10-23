//! Local, evidence-based reputation. Scores come from receipts and ledger facts this node saw;
//! opinions received from others are weighted by the trust already placed in them (EigenTrust-like),
//! so a clique of newcomers rating each other stays at zero.

use std::collections::HashMap;

use alp_grid_core::keys::PublicKey;
use serde::{Deserialize, Serialize};

use crate::seniority::ServiceBook;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub valid_receipts: u32,
    pub invalid_receipts: u32,
    pub challenges_ok: u32,
    pub challenges_failed: u32,
    pub timeouts: u32,
    pub latency_ms_ewma: f32,
}

impl Evidence {
    fn direct_score(&self) -> f32 {
        let good = self.valid_receipts + self.challenges_ok;
        let bad = self.invalid_receipts * 5 + self.challenges_failed * 3 + self.timeouts;
        let n = good + bad;
        if n == 0 {
            return 0.0;
        }
        (good as f32 / (n as f32 + 1.0)).clamp(0.0, 1.0)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Reputation {
    pub evidence: HashMap<PublicKey, Evidence>,
    /// Opinions received: (about, from) -> score in [0, 1]
    pub opinions: HashMap<PublicKey, HashMap<PublicKey, f32>>,
}

impl Reputation {
    pub fn note_receipt(&mut self, peer: PublicKey, valid: bool, latency_ms: f32) {
        let e = self.evidence.entry(peer).or_default();
        if valid {
            e.valid_receipts += 1;
        } else {
            e.invalid_receipts += 1;
        }
        e.latency_ms_ewma = if e.latency_ms_ewma == 0.0 {
            latency_ms
        } else {
            0.8 * e.latency_ms_ewma + 0.2 * latency_ms
        };
    }
    pub fn note_challenge(&mut self, peer: PublicKey, ok: bool) {
        let e = self.evidence.entry(peer).or_default();
        if ok {
            e.challenges_ok += 1;
        } else {
            e.challenges_failed += 1;
        }
    }
    pub fn note_timeout(&mut self, peer: PublicKey) {
        self.evidence.entry(peer).or_default().timeouts += 1;
    }
    pub fn note_opinion(&mut self, about: PublicKey, from: PublicKey, score: f32) {
        self.opinions.entry(about).or_default().insert(from, score.clamp(0.0, 1.0));
    }

    /// Direct trust from this node's own evidence, scaled by seniority so that a newcomer
    /// cannot buy trust with a burst of good answers.
    pub fn direct(&self, peer: &PublicKey, book: &ServiceBook, now: u64) -> f32 {
        let ev = self.evidence.get(peer).map(|e| e.direct_score()).unwrap_or(0.0);
        let sen = book.weight(peer, now);
        // 30 % evidence alone, 70 % evidence × seniority: time matters more than talk
        0.3 * ev + 0.7 * ev * sen
    }

    /// Direct trust blended with others' opinions, each opinion weighted by our direct trust in its author.
    pub fn trust(&self, peer: &PublicKey, book: &ServiceBook, now: u64) -> f32 {
        let direct = self.direct(peer, book, now);
        let Some(ops) = self.opinions.get(peer) else { return direct };
        let mut num = 0.0;
        let mut den = 0.0;
        for (from, score) in ops {
            let w = self.direct(from, book, now);
            num += w * score;
            den += w;
        }
        if den == 0.0 {
            direct
        } else {
            0.6 * direct + 0.4 * (num / den)
        }
    }

    /// Reputation of an operator: average trust of its nodes weighted by their seniority.
    pub fn operator(&self, nodes: &[PublicKey], book: &ServiceBook, now: u64) -> f32 {
        let mut num = 0.0;
        let mut den = 0.0;
        for n in nodes {
            let w = 1.0 + book.seniority(n, now) as f32;
            num += w * self.trust(n, book, now);
            den += w;
        }
        if den == 0.0 {
            0.0
        } else {
            num / den
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alp_grid_core::keys::Keypair;
    use alp_grid_core::time::DAY;

    #[test]
    fn sybil_clique_stays_at_zero() {
        let now = 1_800_000_000;
        let honest: Vec<PublicKey> = (1..=3).map(|i| Keypair::from_seed(&[i; 32]).public()).collect();
        let sybils: Vec<PublicKey> = (100..=110).map(|i| Keypair::from_seed(&[i; 32]).public()).collect();
        let mut book = ServiceBook::default();
        let mut rep = Reputation::default();
        for h in &honest {
            for d in 0..200u64 {
                book.record(*h, now - d * DAY, true);
            }
            for _ in 0..50 {
                rep.note_receipt(*h, true, 20.0);
            }
        }
        // sybils rate each other 1.0, nobody honest ever saw them succeed
        for a in &sybils {
            for b in &sybils {
                if a != b {
                    rep.note_opinion(*a, *b, 1.0);
                }
            }
        }
        for s in &sybils {
            assert_eq!(rep.trust(s, &book, now), 0.0);
        }
        for h in &honest {
            assert!(rep.trust(h, &book, now) > 0.3);
        }
    }

    #[test]
    fn failures_hurt() {
        let now = 1_800_000_000;
        let p = Keypair::from_seed(&[1; 32]).public();
        let mut book = ServiceBook::default();
        for d in 0..100u64 {
            book.record(p, now - d * DAY, true);
        }
        let mut rep = Reputation::default();
        for _ in 0..20 {
            rep.note_receipt(p, true, 10.0);
        }
        let before = rep.trust(&p, &book, now);
        for _ in 0..5 {
            rep.note_receipt(p, false, 10.0);
        }
        assert!(rep.trust(&p, &book, now) < before);
    }
}
