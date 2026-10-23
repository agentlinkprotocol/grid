//! The mandatory scenarios, sized for CI. `grid-sim` runs them bigger.

use std::sync::Arc;

use alp_grid_core::ids::{card_key, zone_key, AgentId};
use alp_grid_core::keys::Keypair;
use alp_grid_core::transport::NetPrefix;
use alp_grid_core::types::{Revocation, RevocationTarget, RevokedBy};
use alp_grid_node::engine::SearchQuery;
use alp_grid_sim::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const NOW: u64 = 1_800_000_000;

fn agent(i: u32) -> Keypair {
    let mut s = [0u8; 32];
    s[..4].copy_from_slice(&(0x7000_0000u32 + i).to_be_bytes());
    Keypair::from_seed(&s)
}

async fn world(nodes: &[usize], agents: usize, seed: u64) -> (Arc<SimNet>, Vec<(AgentId, String)>, Vec<Vec<String>>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let sentences = corpus(&mut rng, 1500);
    let map = Arc::new(map_from_corpus(&sentences, 8, 8, seed));
    let net = SimNet::build(nodes, 16, NOW, map, seed);
    let alive = net.alive();
    let mut entries = Vec::new();
    let mut traits_of = Vec::new();
    for i in 0..agents {
        let a = agent(i as u32);
        let traits: Vec<String> = (0..rng.gen_range(1..=2))
            .map(|_| sentences[rng.gen_range(0..sentences.len())].clone())
            .collect();
        let home = &alive[rng.gen_range(0..alive.len())];
        let r = home.engine.publish_card(agent_card(&home.engine, &a, 1, &traits, NOW)).await.unwrap();
        assert!(r.card_copies > 0, "{:?}", r.rejections);
        for t in &traits {
            entries.push((AgentId::from_pubkey(&a.public()), t.clone()));
        }
        traits_of.push(traits);
    }
    (net, entries, traits_of)
}

async fn recall(net: &Arc<SimNet>, entries: &[(AgentId, String)], n: usize, seed: u64) -> f32 {
    let mut rng = ChaCha20Rng::seed_from_u64(seed + 99);
    let alive = net.alive();
    let mut total = 0f32;
    for _ in 0..n {
        let (_, text) = &entries[rng.gen_range(0..entries.len())];
        let s = &alive[rng.gen_range(0..alive.len())];
        let got = s
            .engine
            .search(SearchQuery {
                text: Some(text.clone()),
                k: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        let ids: Vec<AgentId> = got.results.iter().map(|r| r.agent_id.clone()).collect();
        total += recall_at_k(text, entries, &ids, 10);
    }
    total / n as f32
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recall_against_exact_search() {
    let (net, entries, _) = world(&[6, 6, 6, 6, 6], 120, 1).await;
    let r = recall(&net, &entries, 25, 1).await;
    println!("recall@10 = {r}");
    assert!(r >= 0.9, "recall {r} < 0.9");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_percent_of_nodes_die_no_data_lost() {
    let (net, entries, _) = world(&[8, 8, 8, 8, 8], 100, 2).await;
    let before = recall(&net, &entries, 20, 2).await;
    let nodes = net.alive();
    for n in nodes.iter().take(nodes.len() / 5) {
        net.kill(&n.node_ref.pubkey);
    }
    // immediately after the loss, every card is still retrievable from the survivors
    let survivor = &net.alive()[0];
    for (a, _) in entries.iter() {
        assert!(survivor.engine.get_card(a).await.unwrap().0.is_some(), "card {a} lost");
    }
    net.maintenance().await;
    let after = recall(&net, &entries, 20, 2).await;
    println!("recall before {before} after churn+repair {after}");
    assert!(after >= before - 0.05, "recall dropped from {before} to {after}");
    // repair put copies back on the new guardians
    let (a, _) = &entries[0];
    let guardians = net.guardians(&card_key(a), 20);
    let holding = guardians
        .iter()
        .filter(|g| net.get(&g.pubkey).unwrap().engine.store.get_card(a).unwrap().is_some())
        .count();
    assert!(
        holding >= guardians.len() * 3 / 4,
        "only {holding}/{} guardians hold the card after repair",
        guardians.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_and_version_update_propagate() {
    let (net, _, traits_of) = world(&[5, 5, 5, 5], 30, 3).await;
    let alive = net.alive();
    let a = agent(0);
    let id = AgentId::from_pubkey(&a.public());
    let home = &alive[0];
    // version 2 replaces version 1 everywhere
    let v2_traits = vec!["Quantum computing researcher".to_string()];
    home.engine.publish_card(agent_card(&home.engine, &a, 2, &v2_traits, NOW)).await.unwrap();
    for n in &alive {
        let res = n
            .engine
            .search(SearchQuery {
                text: Some(traits_of[0][0].clone()),
                k: Some(20),
                at: Some(NOW + 1),
                ..Default::default()
            })
            .await
            .unwrap();
        for r in res.results.iter().filter(|r| r.agent_id == id) {
            assert_eq!(r.card_version, 2, "node served an old version");
            assert!(r.matches.iter().all(|m| m.text == "Quantum computing researcher"));
        }
    }
    // an attacker replaying version 1 is refused by every guardian
    let replay = {
        let mut c = agent_card(&home.engine, &a, 1, &traits_of[0], NOW);
        c.countersign(&home.engine.identity.node, NOW).unwrap();
        c
    };
    for g in net.guardians(&card_key(&id), 20) {
        let n = net.get(&g.pubkey).unwrap();
        let resp = n.engine.handle(
            None,
            alp_grid_core::wire::AtlasRequest::Store(alp_grid_core::wire::StoreRequest::Card(replay.clone())),
        );
        let alp_grid_core::wire::AtlasResponse::Store(s) = resp else { panic!() };
        assert!(matches!(s.receipt.outcome, alp_grid_core::types::Outcome::Rejected(_)));
    }
    // revocation: nobody serves the agent any more
    let rev = Revocation::new_signed(&a, id.clone(), RevocationTarget::Card(2), RevokedBy::Agent, NOW + 5).unwrap();
    home.engine.publish_revocation(rev).await.unwrap();
    for n in &alive {
        let res = n
            .engine
            .search(SearchQuery {
                text: Some("Quantum computing researcher".into()),
                k: Some(20),
                at: Some(NOW + 6),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(res.results.iter().all(|r| r.agent_id != id), "revoked agent still served");
        let (c, r) = n.engine.get_card(&id).await.unwrap();
        assert!(c.is_none() && r.is_some());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sybil_operator_never_controls_a_key() {
    // 20 honest nodes across 10 operators, then 100 Sybil nodes under one operator
    let (net, entries, _) = world(&[2; 10], 20, 4).await;
    let sybil_op = Keypair::from_seed(&[0xEE; 32]);
    for i in 0..100u32 {
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(&(0xBAD0_0000u32 + i).to_be_bytes());
        net.add_node(Keypair::from_seed(&s), &sybil_op, NetPrefix(vec![192, 168]), NOW, 0);
    }
    assert_eq!(net.alive().len(), 120);
    for (a, _) in entries.iter().take(10) {
        let g = net.guardians(&card_key(a), 20);
        let sybils = g.iter().filter(|n| n.operator == sybil_op.public()).count();
        assert!(sybils <= 2, "{sybils} sybil guardians for one key");
    }
    for z in 0..net.map.zones() as u32 {
        let g = net.guardians(&zone_key(1, z), 20);
        assert!(g.iter().filter(|n| n.operator == sybil_op.public()).count() <= 2);
    }
    // and a card published after the Sybil flood is still found
    let alive = net.alive();
    let honest = alive.iter().find(|n| n.node_ref.operator != sybil_op.public()).unwrap();
    let a = agent(999);
    honest
        .engine
        .publish_card(agent_card(&honest.engine, &a, 1, &["Volcanologist studying Etna".to_string()], NOW))
        .await
        .unwrap();
    let res = honest
        .engine
        .search(SearchQuery {
            text: Some("volcanologist Etna".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.results[0].agent_id, AgentId::from_pubkey(&a.public()));
}
