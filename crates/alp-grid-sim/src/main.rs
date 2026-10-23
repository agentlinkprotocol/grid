//! `grid-sim`: run a sized simulation and print recall, repair and Sybil figures.

use std::sync::Arc;

use alp_grid_core::ids::{card_key, AgentId};
use alp_grid_core::keys::Keypair;
use alp_grid_node::engine::SearchQuery;
use alp_grid_sim::*;
use anyhow::Result;
use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[derive(Parser)]
#[command(name = "grid-sim", about = "Simulate an Atlas in memory")]
struct Args {
    #[arg(long, default_value_t = 60)]
    nodes: usize,
    #[arg(long, default_value_t = 12)]
    operators: usize,
    #[arg(long, default_value_t = 400)]
    agents: usize,
    #[arg(long, default_value_t = 40)]
    queries: usize,
    #[arg(long, default_value_t = 16)]
    coarse: usize,
    #[arg(long, default_value_t = 8)]
    fine: usize,
    #[arg(long, default_value_t = 20)]
    kill_percent: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let now = 1_800_000_000u64;
    let mut rng = ChaCha20Rng::seed_from_u64(args.seed);
    let sentences = corpus(&mut rng, 4000);
    let map = Arc::new(map_from_corpus(&sentences, args.coarse, args.fine, args.seed));
    let per_op = args.nodes.div_ceil(args.operators);
    let ops: Vec<usize> = (0..args.operators)
        .map(|i| {
            if i == args.operators - 1 {
                args.nodes - per_op * (args.operators - 1)
            } else {
                per_op
            }
        })
        .collect();
    let net = SimNet::build(&ops, 40, now, map, args.seed);
    let nodes = net.alive();
    println!("nodes={} operators={} zones={}", nodes.len(), args.operators, net.map.zones());

    // publish
    let mut entries: Vec<(AgentId, String)> = Vec::new();
    let t0 = std::time::Instant::now();
    for i in 0..args.agents {
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(&(0x7000_0000u32 + i as u32).to_be_bytes());
        let agent = Keypair::from_seed(&s);
        let traits: Vec<String> = (0..rng.gen_range(1..=3))
            .map(|_| sentences[rng.gen_range(0..sentences.len())].clone())
            .collect();
        let home = &nodes[rng.gen_range(0..nodes.len())];
        let card = agent_card(&home.engine, &agent, 1, &traits, now);
        let r = home.engine.publish_card(card).await?;
        if r.card_copies == 0 {
            println!("publish failed: {:?}", r.rejections);
        }
        for t in traits {
            entries.push((AgentId::from_pubkey(&agent.public()), t));
        }
    }
    println!(
        "published {} agents in {:?} ({} requests)",
        args.agents,
        t0.elapsed(),
        net.requests.load(std::sync::atomic::Ordering::Relaxed)
    );

    // recall
    let recall = measure_recall(&net, &entries, args.queries, &mut rng).await;
    println!("recall@10 = {recall:.3}");

    // churn
    let kill = nodes.len() * args.kill_percent / 100;
    for n in nodes.iter().take(kill) {
        net.kill(&n.node_ref.pubkey);
    }
    let imported = net.maintenance().await;
    println!("killed {kill} nodes, repair imported {imported} items");
    let recall2 = measure_recall(&net, &entries, args.queries, &mut rng).await;
    println!("recall@10 after churn + repair = {recall2:.3}");
    let mut found = 0;
    for (a, _) in entries.iter().take(100) {
        let g = net.guardians(&card_key(a), 20);
        let any = net.alive()[0].engine.get_card(a).await?.0.is_some();
        if any {
            found += 1;
        }
        let _ = g;
    }
    println!("cards retrievable after churn: {found}/100");
    Ok(())
}

async fn measure_recall(net: &Arc<SimNet>, entries: &[(AgentId, String)], queries: usize, rng: &mut ChaCha20Rng) -> f32 {
    let alive = net.alive();
    let mut total = 0f32;
    for _ in 0..queries {
        let (_, text) = &entries[rng.gen_range(0..entries.len())];
        let searcher = &alive[rng.gen_range(0..alive.len())];
        let got = searcher
            .engine
            .search(SearchQuery {
                text: Some(text.clone()),
                k: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        let got_ids: Vec<AgentId> = got.results.iter().map(|r| r.agent_id.clone()).collect();
        total += recall_at_k(text, entries, &got_ids, 10);
    }
    total / queries as f32
}
