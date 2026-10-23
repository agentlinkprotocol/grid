//! Node configuration (TOML) and on-disk identity.

use std::path::{Path, PathBuf};

use alp_grid_core::keys::Keypair;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Bootstrap nodes built into the binary. Empty until the first public node runs; `grid init` copies
/// this list into the config, where operators can add their own.
pub const DEFAULT_BOOTSTRAP: &[&str] = &[
    // "/dns4/boot.agentlinkprotocol.org/udp/4001/quic-v1/p2p/12D3Koo…",
    // "/dns4/boot.agentlinkprotocol.org/tcp/4001/p2p/12D3Koo…",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Where keys, the database and the API token live.
    pub data_dir: PathBuf,
    pub network: NetworkSection,
    pub api: ApiSection,
    pub node: NodeSection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSection {
    pub listen: Vec<String>,
    pub bootstrap: Vec<String>,
    /// Disable libp2p entirely: a single-node Atlas, for development.
    pub offline: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiSection {
    pub listen: String,
    /// Allow browser origins (the Console) to read public endpoints.
    pub cors_origins: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSection {
    /// Declared storage capacity in GiB.
    pub capacity_gib: u64,
    /// Observe the network for the Console (`/v1/atlas/stats`).
    pub observer: bool,
    /// `hash` (deterministic, dev) or `onnx` (multilingual-e5-small, requires the `onnx` build feature).
    pub embedder: String,
    /// `dev` or a path to a `map-v*.bin` file.
    pub map: String,
    /// Expected blake3 of the map file (hex); checked when `map` is a path.
    pub map_hash: Option<String>,
    pub pow_bits: u32,
    pub enforce_quota: bool,
    /// Zones probed per search. Network parameter is 4 (65 536-zone map); dev maps use more.
    pub nprobe: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_dir: default_data_dir(),
            network: NetworkSection::default(),
            api: ApiSection::default(),
            node: NodeSection::default(),
        }
    }
}
impl Default for NetworkSection {
    fn default() -> Self {
        NetworkSection {
            listen: vec!["/ip4/0.0.0.0/udp/4001/quic-v1".into(), "/ip4/0.0.0.0/tcp/4001".into()],
            bootstrap: vec![],
            offline: false,
        }
    }
}
impl Default for ApiSection {
    fn default() -> Self {
        ApiSection {
            listen: "127.0.0.1:7777".into(),
            cors_origins: vec![],
        }
    }
}
impl Default for NodeSection {
    fn default() -> Self {
        NodeSection {
            capacity_gib: 10,
            observer: false,
            embedder: "hash".into(),
            map: "dev".into(),
            map_hash: None,
            pow_bits: 20,
            enforce_quota: true,
            nprobe: alp_grid_core::params::NPROBE,
        }
    }
}

pub fn default_data_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".grid")
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(toml::from_str(&text)?)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("grid.redb")
    }
    pub fn key_path(&self) -> PathBuf {
        self.data_dir.join("node.key")
    }
    pub fn token_path(&self) -> PathBuf {
        self.data_dir.join("api.token")
    }
}

/// Load or create the node key (32-byte Ed25519 seed, hex, mode 0600).
pub fn load_or_create_key(path: &Path) -> Result<Keypair> {
    if path.exists() {
        let hex_seed = std::fs::read_to_string(path)?.trim().to_string();
        let bytes = hex::decode(&hex_seed).context("node.key is not hex")?;
        let seed: [u8; 32] = bytes.as_slice().try_into().context("node.key must be 32 bytes")?;
        return Ok(Keypair::from_seed(&seed));
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let kp = Keypair::generate();
    std::fs::write(path, hex::encode(kp.seed()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(kp)
}

/// Load or create the local API bearer token.
pub fn load_or_create_token(path: &Path) -> Result<String> {
    if path.exists() {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let token = format!("grid_{}", hex::encode(bytes));
    std::fs::write(path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}
