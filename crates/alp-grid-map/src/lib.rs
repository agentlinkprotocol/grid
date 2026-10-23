//! The semantic map: a two-level set of centroids shared by every node, identical everywhere.
//!
//! `zone_id = coarse_index * fine_count + fine_index`. Assignment is nearest coarse centroid,
//! then nearest fine centroid inside that coarse group. A vector also belongs to a second zone
//! when `sim2 >= sim1 - SECOND_ZONE_MARGIN`.
//!
//! File format `map-v<N>.bin` (little endian):
//! `magic "ALPMAP01" | version u32 | dim u16 | coarse u16 | fine u16 | coarse centroids f16[] | fine centroids f16[]`.
//! The blake3 of the whole file is the map hash pinned in the binary.

use alp_grid_core::params::{DIM, SECOND_ZONE_MARGIN};
use alp_grid_core::types::Vector;
use alp_grid_core::Bytes32;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

pub mod corpus;
pub mod kmeans;

pub const MAGIC: &[u8; 8] = b"ALPMAP01";

#[derive(Debug, Error)]
pub enum MapError {
    #[error("bad map file: {0}")]
    Format(String),
    #[error("map hash mismatch: expected {expected}, got {got}")]
    Hash { expected: String, got: String },
    #[error("vector dimension {got} does not match map dimension {expected}")]
    Dim { expected: usize, got: usize },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ZoneMatch {
    pub zone_id: u32,
    pub sim: f32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Assignment {
    pub primary: ZoneMatch,
    pub second: Option<ZoneMatch>,
}

impl Assignment {
    pub fn zones(&self) -> Vec<u32> {
        let mut z = vec![self.primary.zone_id];
        if let Some(s) = self.second {
            z.push(s.zone_id);
        }
        z
    }
    pub fn contains(&self, zone_id: u32) -> bool {
        self.primary.zone_id == zone_id || self.second.map(|s| s.zone_id == zone_id).unwrap_or(false)
    }
}

#[derive(Clone)]
pub struct Map {
    pub version: u32,
    pub dim: usize,
    pub coarse_n: usize,
    pub fine_n: usize,
    coarse: Vec<f32>,
    fine: Vec<f32>,
    hash: Bytes32,
}

impl std::fmt::Debug for Map {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Map(v{}, {}x{} zones, dim {}, {})",
            self.version,
            self.coarse_n,
            self.fine_n,
            self.dim,
            &self.hash.to_hex()[..16]
        )
    }
}

fn normalize(v: &mut [f32]) {
    let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        for x in v {
            *x /= n;
        }
    }
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

impl Map {
    pub fn from_centroids(version: u32, dim: usize, coarse_n: usize, fine_n: usize, mut coarse: Vec<f32>, mut fine: Vec<f32>) -> Result<Self, MapError> {
        if coarse.len() != coarse_n * dim || fine.len() != coarse_n * fine_n * dim {
            return Err(MapError::Format("centroid counts do not match header".into()));
        }
        for c in coarse.chunks_exact_mut(dim) {
            normalize(c);
        }
        for c in fine.chunks_exact_mut(dim) {
            normalize(c);
        }
        let mut m = Map {
            version,
            dim,
            coarse_n,
            fine_n,
            coarse,
            fine,
            hash: Bytes32::zero(),
        };
        m.hash = Bytes32(*blake3::hash(&m.to_bytes()).as_bytes());
        Ok(m)
    }

    /// A small deterministic map for development and tests (16 x 16 = 256 zones by default).
    pub fn dev(version: u32, coarse_n: usize, fine_n: usize, seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut coarse = Vec::with_capacity(coarse_n * DIM);
        for _ in 0..coarse_n * DIM {
            coarse.push(rng.gen_range(-1.0f32..1.0));
        }
        // fine centroids = coarse + small jitter, so the hierarchy is consistent
        let mut fine = Vec::with_capacity(coarse_n * fine_n * DIM);
        for c in 0..coarse_n {
            let base = &coarse[c * DIM..(c + 1) * DIM];
            for _ in 0..fine_n {
                for b in base {
                    fine.push(b + rng.gen_range(-0.35f32..0.35));
                }
            }
        }
        Self::from_centroids(version, DIM, coarse_n, fine_n, coarse, fine).expect("dev map is well formed")
    }

    /// Build a map from sample vectors by hierarchical spherical k-means. Deterministic by seed.
    pub fn build(version: u32, points: &[Vec<f32>], coarse_n: usize, fine_n: usize, iters: usize, seed: u64) -> Result<Self, MapError> {
        if points.is_empty() {
            return Err(MapError::Format("no points".into()));
        }
        let dim = points[0].len();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (coarse, assign) = kmeans::spherical_kmeans(points, coarse_n, iters, &mut rng);
        let mut fine = Vec::with_capacity(coarse_n * fine_n * dim);
        for c in 0..coarse_n {
            let members: Vec<Vec<f32>> = points.iter().zip(&assign).filter(|(_, a)| **a == c).map(|(v, _)| v.clone()).collect();
            if members.len() >= fine_n {
                let (fc, _) = kmeans::spherical_kmeans(&members, fine_n, iters, &mut rng);
                fine.extend(fc);
            } else {
                let base = &coarse[c * dim..(c + 1) * dim];
                for _ in 0..fine_n {
                    for b in base {
                        fine.push(b + rng.gen_range(-0.05f32..0.05));
                    }
                }
            }
        }
        Self::from_centroids(version, dim, coarse_n, fine_n, coarse, fine)
    }

    /// Development map that follows real data: hierarchical k-means on a synthetic multilingual
    /// corpus embedded with the deterministic dev embedder. Same arguments, same bytes.
    pub fn dev_semantic(version: u32, coarse_n: usize, fine_n: usize, sentences: usize, seed: u64) -> Self {
        use alp_grid_embed::Embedder;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let corpus = corpus::generate(&mut rng, sentences);
        let refs: Vec<&str> = corpus.iter().map(|s| s.as_str()).collect();
        let pts: Vec<Vec<f32>> = alp_grid_embed::HashEmbedder::new()
            .embed_batch(&refs)
            .expect("hash embedder")
            .into_iter()
            .map(|v| v.0)
            .collect();
        Self::build(version, &pts, coarse_n, fine_n, 10, seed).expect("dev map")
    }

    pub fn zones(&self) -> usize {
        self.coarse_n * self.fine_n
    }

    pub fn hash(&self) -> Bytes32 {
        self.hash
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 10 + (self.coarse.len() + self.fine.len()) * 2);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.dim as u16).to_le_bytes());
        out.extend_from_slice(&(self.coarse_n as u16).to_le_bytes());
        out.extend_from_slice(&(self.fine_n as u16).to_le_bytes());
        for v in self.coarse.iter().chain(self.fine.iter()) {
            out.extend_from_slice(&half::f16::from_f32(*v).to_le_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, MapError> {
        if b.len() < 18 || &b[..8] != MAGIC {
            return Err(MapError::Format("bad magic".into()));
        }
        let version = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let dim = u16::from_le_bytes([b[12], b[13]]) as usize;
        let coarse_n = u16::from_le_bytes([b[14], b[15]]) as usize;
        let fine_n = u16::from_le_bytes([b[16], b[17]]) as usize;
        let body = &b[18..];
        let expected = (coarse_n * dim + coarse_n * fine_n * dim) * 2;
        if body.len() != expected {
            return Err(MapError::Format(format!("expected {expected} centroid bytes, got {}", body.len())));
        }
        let floats: Vec<f32> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| half::f16::from_le_bytes([c[0], c[1]]).to_f32())
            .collect();
        let (coarse, fine) = floats.split_at(coarse_n * dim);
        let m = Self::from_centroids(version, dim, coarse_n, fine_n, coarse.to_vec(), fine.to_vec())?;
        Ok(m)
    }

    pub fn load(path: &std::path::Path, expected_hash: Option<&Bytes32>) -> Result<Self, MapError> {
        let bytes = std::fs::read(path)?;
        let got = Bytes32(*blake3::hash(&bytes).as_bytes());
        if let Some(exp) = expected_hash {
            if &got != exp {
                return Err(MapError::Hash {
                    expected: exp.to_hex(),
                    got: got.to_hex(),
                });
            }
        }
        Self::from_bytes(&bytes)
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), MapError> {
        std::fs::write(path, self.to_bytes())?;
        Ok(())
    }

    fn check_dim(&self, v: &Vector) -> Result<(), MapError> {
        if v.dim() != self.dim {
            return Err(MapError::Dim {
                expected: self.dim,
                got: v.dim(),
            });
        }
        Ok(())
    }

    fn coarse_ranked(&self, v: &[f32]) -> Vec<(usize, f32)> {
        let mut r: Vec<(usize, f32)> = (0..self.coarse_n)
            .map(|c| (c, dot(v, &self.coarse[c * self.dim..(c + 1) * self.dim])))
            .collect();
        r.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        r
    }

    fn fine_in(&self, coarse_idx: usize, v: &[f32]) -> Vec<ZoneMatch> {
        let base = coarse_idx * self.fine_n;
        (0..self.fine_n)
            .map(|f| {
                let i = base + f;
                ZoneMatch {
                    zone_id: i as u32,
                    sim: dot(v, &self.fine[i * self.dim..(i + 1) * self.dim]),
                }
            })
            .collect()
    }

    /// The `n` nearest zones, searched inside the 2 nearest coarse groups (used for nprobe and decoys).
    pub fn nearest(&self, v: &Vector, n: usize) -> Result<Vec<ZoneMatch>, MapError> {
        self.check_dim(v)?;
        let ranked = self.coarse_ranked(&v.0);
        let mut cands: Vec<ZoneMatch> = Vec::with_capacity(2 * self.fine_n);
        for (c, _) in ranked.iter().take(2) {
            cands.extend(self.fine_in(*c, &v.0));
        }
        cands.sort_by(|a, b| b.sim.partial_cmp(&a.sim).unwrap_or(std::cmp::Ordering::Equal));
        cands.truncate(n);
        Ok(cands)
    }

    /// Primary zone and, when close enough, second zone.
    pub fn assign(&self, v: &Vector) -> Result<Assignment, MapError> {
        let top = self.nearest(v, 2)?;
        let primary = top[0];
        let second = top.get(1).copied().filter(|s| s.sim >= primary.sim - SECOND_ZONE_MARGIN);
        Ok(Assignment { primary, second })
    }

    /// Does `v` belong to `zone_id` (as primary or second zone)? Guardians use this to refuse misplaced entries.
    pub fn belongs(&self, v: &Vector, zone_id: u32) -> Result<bool, MapError> {
        Ok(self.assign(v)?.contains(zone_id))
    }

    /// Deterministic decoy zones for query privacy: pseudo-random zones derived from a nonce.
    pub fn decoys(&self, nonce: u64, n: usize, exclude: &[u32]) -> Vec<u32> {
        let mut rng = ChaCha20Rng::seed_from_u64(nonce);
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let z = rng.gen_range(0..self.zones() as u32);
            if !exclude.contains(&z) && !out.contains(&z) {
                out.push(z);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_map_roundtrip_and_hash() {
        let m = Map::dev(1, 4, 4, 42);
        let bytes = m.to_bytes();
        let back = Map::from_bytes(&bytes).unwrap();
        assert_eq!(back.hash(), m.hash());
        assert_eq!(back.zones(), 16);
        assert_eq!(Map::dev(1, 4, 4, 42).hash(), m.hash());
        assert_ne!(Map::dev(1, 4, 4, 43).hash(), m.hash());
    }

    #[test]
    fn assignment_is_stable_and_in_range() {
        let m = Map::dev(1, 16, 16, 1);
        let mut v = Vector(vec![0.1; DIM]);
        v.0[3] = 2.0;
        v.normalize();
        let a = m.assign(&v).unwrap();
        assert!((a.primary.zone_id as usize) < m.zones());
        assert_eq!(m.assign(&v).unwrap(), a);
        assert!(m.belongs(&v, a.primary.zone_id).unwrap());
        let near = m.nearest(&v, 4).unwrap();
        assert_eq!(near.len(), 4);
        assert_eq!(near[0].zone_id, a.primary.zone_id);
    }

    #[test]
    fn decoys_exclude_real_zones() {
        let m = Map::dev(1, 4, 4, 1);
        let d = m.decoys(7, 2, &[0, 1, 2, 3]);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|z| *z > 3));
        assert_eq!(m.decoys(7, 2, &[0, 1, 2, 3]), d);
    }
}
