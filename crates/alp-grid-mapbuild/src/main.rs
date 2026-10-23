//! `grid-mapbuild`: builds a semantic map reproducibly. Same seed, same corpus size, same model
//! => same bytes, same blake3 hash. Anyone can rebuild the published map and check the hash.

use alp_grid_map::corpus;

use std::path::PathBuf;

use alp_grid_core::params::DIM;
use alp_grid_embed::{Embedder, HashEmbedder};
use alp_grid_map::Map;
use anyhow::Result;
use clap::Parser;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[derive(Parser, Debug)]
#[command(name = "grid-mapbuild", about = "Build the Atlas semantic map (hierarchical spherical k-means)")]
struct Args {
    /// Map version number written in the file header.
    #[arg(long, default_value_t = 1)]
    version: u32,
    /// Coarse centroids.
    #[arg(long, default_value_t = 16)]
    coarse: usize,
    /// Fine centroids per coarse centroid.
    #[arg(long, default_value_t = 16)]
    fine: usize,
    /// Number of synthetic sentences in the corpus.
    #[arg(long, default_value_t = 20_000)]
    sentences: usize,
    /// Lloyd iterations per level.
    #[arg(long, default_value_t = 12)]
    iters: usize,
    /// Random seed; the published map pins this value.
    #[arg(long, default_value_t = 20261023)]
    seed: u64,
    /// Output file.
    #[arg(long, default_value = "map-dev.bin")]
    out: PathBuf,
    /// Also dump the corpus next to the map for audit.
    #[arg(long)]
    dump_corpus: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut rng = ChaCha20Rng::seed_from_u64(args.seed);
    eprintln!("corpus: generating {} sentences…", args.sentences);
    let sentences = corpus::generate(&mut rng, args.sentences);
    if args.dump_corpus {
        std::fs::write(args.out.with_extension("corpus.txt"), sentences.join("\n"))?;
    }
    let embedder = HashEmbedder::new();
    eprintln!("embedding with {}…", embedder.model_id());
    let refs: Vec<&str> = sentences.iter().map(|s| s.as_str()).collect();
    let vectors: Vec<Vec<f32>> = embedder.embed_batch(&refs)?.into_iter().map(|v| v.0).collect();

    eprintln!("hierarchical k-means: {} x {} centroids…", args.coarse, args.fine);
    let map = Map::build(args.version, &vectors, args.coarse, args.fine, args.iters, args.seed)?;
    let _ = DIM;
    map.save(&args.out)?;
    println!("{}", map.hash().to_hex());
    eprintln!("wrote {} ({} zones), blake3 above", args.out.display(), map.zones());
    Ok(())
}
