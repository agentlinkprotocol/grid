//! Guardian selection: the closest nodes to a key, with at most 2 per operator and 2 per network
//! prefix (/16 IPv4, /48 IPv6), seniors first among equals.

use std::collections::HashMap;
use std::net::IpAddr;

use alp_grid_core::ids::Position;
use alp_grid_core::keys::PublicKey;
use alp_grid_core::params::{MAX_GUARDIANS_PER_OPERATOR, MAX_GUARDIANS_PER_PREFIX};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetPrefix(pub Vec<u8>);

impl NetPrefix {
    pub fn of(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => NetPrefix(v4.octets()[..2].to_vec()),
            IpAddr::V6(v6) => NetPrefix(v6.octets()[..6].to_vec()),
        }
    }
    pub fn unknown() -> Self {
        NetPrefix(vec![])
    }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub pubkey: PublicKey,
    pub operator: PublicKey,
    pub prefix: NetPrefix,
    pub seniority: u32,
    /// Fill ratio in [0, 1]; above the overflow threshold a node refuses new copies.
    pub fill: f32,
}

/// Pick up to `k` guardians for `key`.
pub fn select_guardians(key: &Position, candidates: &[Candidate], k: usize, overflow: f32) -> Vec<Candidate> {
    let mut ranked: Vec<(&Candidate, [u8; 32])> = candidates.iter().map(|c| (c, Position::of_node(&c.pubkey).distance(key))).collect();
    // closeness first; among (practically) equal distances, seniority decides
    ranked.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.seniority.cmp(&a.0.seniority)));
    let mut per_op: HashMap<PublicKey, usize> = HashMap::new();
    let mut per_prefix: HashMap<NetPrefix, usize> = HashMap::new();
    let mut out = Vec::with_capacity(k);
    for (c, _) in ranked {
        if out.len() >= k {
            break;
        }
        if c.fill >= overflow {
            continue;
        }
        let op = per_op.entry(c.operator).or_insert(0);
        if *op >= MAX_GUARDIANS_PER_OPERATOR {
            continue;
        }
        let known_prefix = !c.prefix.0.is_empty();
        if known_prefix {
            let pf = per_prefix.entry(c.prefix.clone()).or_insert(0);
            if *pf >= MAX_GUARDIANS_PER_PREFIX {
                continue;
            }
            *pf += 1;
        }
        *op += 1;
        out.push(c.clone());
    }
    out
}

/// Would `me` be an excess guardian for `key` given the others? (A guardian in excess does not store.)
pub fn is_excess(key: &Position, me: &Candidate, others: &[Candidate], k: usize, overflow: f32) -> bool {
    let mut all = others.to_vec();
    all.push(me.clone());
    !select_guardians(key, &all, k, overflow).iter().any(|c| c.pubkey == me.pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alp_grid_core::keys::{Bytes32, Keypair};

    #[test]
    fn caps_per_operator_and_prefix() {
        let big_op = Keypair::from_seed(&[200; 32]).public();
        let mut cands = Vec::new();
        for i in 1..=40u8 {
            let pk = Keypair::from_seed(&[i; 32]).public();
            let operator = if i <= 30 { big_op } else { Keypair::from_seed(&[100 + i; 32]).public() };
            let prefix = if i <= 30 { NetPrefix(vec![10, 0]) } else { NetPrefix(vec![10, i]) };
            cands.push(Candidate {
                pubkey: pk,
                operator,
                prefix,
                seniority: i as u32,
                fill: 0.1,
            });
        }
        let key = Position(Bytes32([7; 32]));
        let g = select_guardians(&key, &cands, 20, 0.8);
        assert_eq!(g.iter().filter(|c| c.operator == big_op).count(), 2);
        assert!(g.len() <= 12); // 2 from the big operator + 10 small ones
        let full = Candidate {
            pubkey: Keypair::from_seed(&[250; 32]).public(),
            operator: Keypair::from_seed(&[251; 32]).public(),
            prefix: NetPrefix::unknown(),
            seniority: 400,
            fill: 0.95,
        };
        cands.push(full.clone());
        assert!(is_excess(&key, &full, &cands, 20, 0.8));
    }
}
