//! `grid`: The Grid node binary.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alp_grid_balance::Capacity;
use alp_grid_core::keys::Keypair;
use alp_grid_embed::{Embedder, HashEmbedder};
use alp_grid_map::Map;
use alp_grid_net::{NetConfig, Network};
use alp_grid_node::api::{self, ApiState};
use alp_grid_node::config::{self, Config};
use alp_grid_node::engine::{Engine, Identity, SearchQuery};
use alp_grid_node::observer;
use alp_grid_store::Store;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "grid", version, about = "The Grid: join the Agent Link Protocol Atlas")]
struct Cli {
    /// Config file (default: <data_dir>/grid.toml, created by `grid init`).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a default config and create the node key.
    Init {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Single-node development Atlas (no libp2p, quota disabled, dev map).
        #[arg(long)]
        dev: bool,
        /// Enable observer mode for the Console.
        #[arg(long)]
        observer: bool,
    },
    /// Run the node.
    Run,
    /// Print the local API bearer token.
    Token,
    /// Print the OpenAPI document.
    Openapi,
    /// Search the Atlas through a running node.
    Search {
        text: String,
        #[arg(long)]
        at: Option<u64>,
        #[arg(long, default_value = "http://127.0.0.1:7777")]
        api: String,
    },
    /// Show a running node's status.
    Status {
        #[arg(long, default_value = "http://127.0.0.1:7777")]
        api: String,
    },
    /// Generate a fresh Ed25519 seed (hex) for an agent or a node.
    Keygen,
    /// Print this node's libp2p peer id and the multiaddrs to give to other operators (no running node needed).
    PeerId {
        /// Public DNS name or IP of this server, e.g. boot.example.org
        #[arg(long)]
        host: Option<String>,
    },
}

fn config_path(cli: &Cli) -> PathBuf {
    cli.config.clone().unwrap_or_else(|| config::default_data_dir().join("grid.toml"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,libp2p=warn".into()))
        .init();
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Init { data_dir, dev, observer } => {
            let mut cfg = Config::default();
            if let Some(d) = data_dir {
                cfg.data_dir = d.clone();
            }
            if *dev {
                cfg.network.offline = true;
                cfg.node.enforce_quota = false;
                cfg.node.pow_bits = 8;
            }
            if cfg.node.map == "dev" {
                cfg.node.nprobe = 16;
            }
            cfg.node.observer = *observer;
            if *observer {
                cfg.api.cors_origins = vec!["*".into()];
            }
            let path = cli.config.clone().unwrap_or_else(|| cfg.data_dir.join("grid.toml"));
            cfg.save(&path)?;
            let kp = config::load_or_create_key(&cfg.key_path())?;
            let token = config::load_or_create_token(&cfg.token_path())?;
            println!("config:   {}", path.display());
            println!("node key: {} (pubkey {})", cfg.key_path().display(), kp.public().to_hex());
            println!("token:    {token}");
            println!(
                "next:     grid run{}",
                if cli.config.is_some() {
                    format!(" --config {}", path.display())
                } else {
                    String::new()
                }
            );
        }
        Cmd::Run => run(Config::load(&config_path(&cli))?).await?,
        Cmd::Token => {
            let cfg = Config::load(&config_path(&cli))?;
            println!("{}", config::load_or_create_token(&cfg.token_path())?);
        }
        Cmd::Openapi => println!("{}", api::openapi_json()),
        Cmd::Keygen => {
            let kp = Keypair::generate();
            println!("seed:   {}", hex::encode(kp.seed()));
            println!("pubkey: {}", kp.public().to_hex());
            println!("agent:  {}", alp_grid_core::ids::AgentId::from_pubkey(&kp.public()));
        }
        Cmd::PeerId { host } => {
            let cfg = Config::load(&config_path(&cli))?;
            let kp = config::load_or_create_key(&cfg.key_path())?;
            let pid = alp_grid_net::peer_id_of(&kp.public()).context("deriving peer id")?;
            println!("peer id: {pid}");
            if let Some(h) = host {
                let proto = if h.parse::<std::net::Ipv4Addr>().is_ok() {
                    "ip4"
                } else if h.parse::<std::net::Ipv6Addr>().is_ok() {
                    "ip6"
                } else {
                    "dns4"
                };
                let port = cfg
                    .network
                    .listen
                    .iter()
                    .find_map(|a| a.split('/').skip_while(|p| *p != "udp" && *p != "tcp").nth(1).map(|p| p.to_string()))
                    .unwrap_or_else(|| "4001".into());
                println!("bootstrap addresses to publish:");
                println!("  /{proto}/{h}/udp/{port}/quic-v1/p2p/{pid}");
                println!("  /{proto}/{h}/tcp/{port}/p2p/{pid}");
            }
        }
        Cmd::Search { text, at, api } => {
            let cfg = Config::load(&config_path(&cli))?;
            let token = config::load_or_create_token(&cfg.token_path())?;
            let body = serde_json::to_string(&SearchQuery {
                text: Some(text.clone()),
                at: *at,
                ..Default::default()
            })?;
            let out = http_post(&format!("{api}/v1/search"), &token, &body).await?;
            println!("{out}");
        }
        Cmd::Status { api } => {
            let cfg = Config::load(&config_path(&cli))?;
            let token = config::load_or_create_token(&cfg.token_path())?;
            println!("{}", http_get(&format!("{api}/v1/status"), &token).await?);
        }
    }
    Ok(())
}

async fn http_post(url: &str, token: &str, body: &str) -> Result<String> {
    let out = tokio::process::Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
            url,
        ])
        .output()
        .await?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

async fn http_get(url: &str, token: &str) -> Result<String> {
    let out = tokio::process::Command::new("curl")
        .args(["-s", "-H", &format!("Authorization: Bearer {token}"), url])
        .output()
        .await?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

async fn run(cfg: Config) -> Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    let node_key = config::load_or_create_key(&cfg.key_path())?;
    let token = config::load_or_create_token(&cfg.token_path())?;
    let now = alp_grid_core::time::now();

    info!(pubkey = %node_key.public().to_hex(), "solving identity proof of work ({} bits)…", cfg.node.pow_bits);
    let identity = Identity::self_operated(node_key.clone(), now, cfg.node.pow_bits)?;
    info!(nonce = identity.pow_nonce, "identity ready");

    let map = Arc::new(match cfg.node.map.as_str() {
        "dev" => {
            info!("building the development map (256 zones) from the synthetic corpus…");
            Map::dev_semantic(1, 16, 16, 3000, 20261023)
        }
        path => {
            let expected = cfg.node.map_hash.as_deref().map(alp_grid_core::Bytes32::from_hex).transpose()?;
            Map::load(std::path::Path::new(path), expected.as_ref()).context("loading map")?
        }
    });
    info!(?map, "semantic map loaded");

    let embedder: Arc<dyn Embedder> = match cfg.node.embedder.as_str() {
        "hash" => Arc::new(HashEmbedder::new()),
        #[cfg(feature = "onnx")]
        "onnx" => Arc::new(alp_grid_embed::onnx::OnnxEmbedder::new(Some(cfg.data_dir.join("models")))?),
        other => anyhow::bail!("unknown embedder '{other}' (build with --features onnx for the real model)"),
    };
    info!(model = embedder.model_id(), "embedder ready");

    let store = Arc::new(Store::open(&cfg.db_path())?);
    let capacity = Capacity {
        declared_bytes: cfg.node.capacity_gib << 30,
        used_bytes: store.stats().map(|s| s.bytes_on_disk).unwrap_or(0),
    };
    let engine = Arc::new(Engine::new(identity.clone(), store, map, embedder, capacity, cfg.node.enforce_quota)?);
    engine.nprobe.store(cfg.node.nprobe.max(1), std::sync::atomic::Ordering::Relaxed);

    let listen_addrs = Arc::new(parking_lot::RwLock::new(Vec::new()));
    if !cfg.network.offline {
        let net_cfg = NetConfig {
            listen: cfg.network.listen.iter().filter_map(|a| a.parse().ok()).collect(),
            bootstrap: cfg.network.bootstrap.iter().filter_map(|a| a.parse().ok()).collect(),
            operator_pubkey: identity.operator.public(),
            ..NetConfig::default()
        };
        let net = Network::start(node_key.seed(), net_cfg, engine.clone()).await?;
        engine.set_transport(net.clone());
        let la = listen_addrs.clone();
        let net2 = net.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                *la.write() = net2.listeners().await.iter().map(|a| format!("{a}/p2p/{}", net2.local_peer_id())).collect();
            }
        });
    } else {
        warn!("offline mode: this node is its own Atlas");
    }

    // periodic duties
    {
        let e = engine.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(alp_grid_core::params::DRAND_ROUND_SECS));
            loop {
                tick.tick().await;
                let r = e.run_challenge_round().await;
                if r.challenged > 0 {
                    info!(round = r.round, challenged = r.challenged, failed = r.failed, "challenge round");
                }
            }
        });
    }
    {
        let e = engine.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                let n = e.sync_round().await;
                let x = e.expire_tick();
                let r = e.republish_due().await;
                info!(imported = n, expired = x, republished = r.len(), "maintenance");
            }
        });
    }
    if cfg.node.observer {
        let e = engine.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                observer::sample(&e);
            }
        });
    }

    let state = ApiState {
        engine: engine.clone(),
        token: Arc::new(token),
        observer: cfg.node.observer,
        listen_addrs,
    };
    let app = api::router(state, &cfg.api.cors_origins);
    let listener = tokio::net::TcpListener::bind(&cfg.api.listen)
        .await
        .with_context(|| format!("binding API on {}", cfg.api.listen))?;
    info!(api = %cfg.api.listen, "local API ready (token in {})", cfg.token_path().display());
    axum::serve(listener, app).await?;
    Ok(())
}
