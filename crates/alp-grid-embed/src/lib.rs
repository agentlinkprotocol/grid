//! Text -> vector. Every node runs the same model, so every guardian recomputes the same vectors.
//!
//! * [`HashEmbedder`]: deterministic bag-of-words/trigram embedding, no model download. Used by
//!   tests, the simulator and development nodes. Similar texts get similar vectors; it is not semantic.
//! * `OnnxEmbedder` (feature `onnx`): `multilingual-e5-small` through fastembed, the real `alp-embed-v1`.

use alp_grid_core::params::{DIM, MODEL_V1};
use alp_grid_core::types::Vector;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmbedError {
    #[error("model error: {0}")]
    Model(String),
}

pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    fn dim(&self) -> usize;
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vector>, EmbedError>;
    fn embed(&self, text: &str) -> Result<Vector, EmbedError> {
        Ok(self.embed_batch(&[text])?.remove(0))
    }
}

/// Deterministic feature-hashing embedder. Model id `alp-embed-dev` so that dev cards are never
/// mistaken for production ones unless `pretend_v1` is set (simulator and tests).
pub struct HashEmbedder {
    model_id: &'static str,
}

impl Default for HashEmbedder {
    fn default() -> Self {
        HashEmbedder { model_id: "alp-embed-dev" }
    }
}

impl HashEmbedder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Report `alp-embed-v1` as model id. Only for tests and the simulator.
    pub fn pretend_v1() -> Self {
        HashEmbedder { model_id: MODEL_V1 }
    }

    fn features(text: &str) -> Vec<(String, f32)> {
        let lower = text.to_lowercase();
        let mut f = Vec::new();
        for w in lower.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) {
            f.push((format!("w:{w}"), 1.0));
            let chars: Vec<char> = w.chars().collect();
            if chars.len() >= 3 {
                for i in 0..=chars.len() - 3 {
                    let tri: String = chars[i..i + 3].iter().collect();
                    f.push((format!("t:{tri}"), 0.35));
                }
            }
            if chars.len() > 5 {
                let stem: String = chars[..5].iter().collect();
                f.push((format!("s:{stem}"), 0.6));
            }
        }
        f
    }
}

impl Embedder for HashEmbedder {
    fn model_id(&self) -> &str {
        self.model_id
    }
    fn dim(&self) -> usize {
        DIM
    }
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vector>, EmbedError> {
        Ok(texts
            .iter()
            .map(|t| {
                let mut v = vec![0f32; DIM];
                for (feat, w) in Self::features(t) {
                    let h = blake3::hash(feat.as_bytes());
                    let b = h.as_bytes();
                    // two buckets per feature for a denser vector
                    for k in 0..2 {
                        let idx = u16::from_le_bytes([b[k * 4], b[k * 4 + 1]]) as usize % DIM;
                        let sign = if b[k * 4 + 2] & 1 == 0 { 1.0 } else { -1.0 };
                        v[idx] += sign * w;
                    }
                }
                let mut vec = Vector(v);
                vec.normalize();
                if vec.0.iter().all(|x| *x == 0.0) {
                    vec.0[0] = 1.0;
                }
                vec
            })
            .collect())
    }
}

#[cfg(feature = "onnx")]
pub mod onnx {
    use super::*;
    use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
    use parking_lot::Mutex;

    /// `multilingual-e5-small`, 384 dimensions, L2-normalised. This is `alp-embed-v1`.
    pub struct OnnxEmbedder {
        model: Mutex<TextEmbedding>,
    }

    impl OnnxEmbedder {
        pub fn new(cache_dir: Option<std::path::PathBuf>) -> Result<Self, EmbedError> {
            let mut opts = InitOptions::new(EmbeddingModel::MultilingualE5Small).with_show_download_progress(false);
            if let Some(d) = cache_dir {
                opts = opts.with_cache_dir(d);
            }
            let model = TextEmbedding::try_new(opts).map_err(|e| EmbedError::Model(e.to_string()))?;
            Ok(OnnxEmbedder { model: Mutex::new(model) })
        }
    }

    impl Embedder for OnnxEmbedder {
        fn model_id(&self) -> &str {
            MODEL_V1
        }
        fn dim(&self) -> usize {
            DIM
        }
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vector>, EmbedError> {
            // e5 expects "query: " / "passage: " prefixes; the Atlas uses "query: " for both so that
            // guardians and searchers compute identical vectors for identical text.
            let prefixed: Vec<String> = texts.iter().map(|t| format!("query: {t}")).collect();
            let out = self.model.lock().embed(prefixed, None).map_err(|e| EmbedError::Model(e.to_string()))?;
            Ok(out
                .into_iter()
                .map(|v| {
                    let mut vec = Vector(v);
                    vec.normalize();
                    vec
                })
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_similar() {
        let e = HashEmbedder::new();
        let a = e.embed("Software developer").unwrap();
        let b = e.embed("software developer").unwrap();
        let c = e.embed("Senior software developer in Paris").unwrap();
        let d = e.embed("Professional hairdresser").unwrap();
        assert_eq!(a.dim(), DIM);
        assert!((a.dot(&b) - 1.0).abs() < 1e-5);
        assert!(a.dot(&c) > a.dot(&d));
        assert!((a.dot(&a) - 1.0).abs() < 1e-4);
    }
}
