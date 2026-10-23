//! Spherical k-means (cosine), Lloyd iterations, k-means++ seeding, deterministic by seed.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn normalize(v: &mut [f32]) {
    let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        for x in v {
            *x /= n;
        }
    }
}

/// Returns `k` centroids (flat, k × dim) and the assignment of each point.
pub fn spherical_kmeans(points: &[Vec<f32>], k: usize, iters: usize, rng: &mut ChaCha20Rng) -> (Vec<f32>, Vec<usize>) {
    let dim = points[0].len();
    let n = points.len();
    let k = k.min(n).max(1);
    // k-means++ seeding
    let mut centroids: Vec<Vec<f32>> = Vec::with_capacity(k);
    centroids.push(points[rng.gen_range(0..n)].clone());
    let mut d2: Vec<f32> = points.iter().map(|p| 1.0 - dot(p, &centroids[0])).collect();
    while centroids.len() < k {
        let total: f32 = d2.iter().sum();
        let mut pick = rng.gen_range(0.0..total.max(1e-9));
        let mut idx = 0;
        for (i, d) in d2.iter().enumerate() {
            pick -= d;
            if pick <= 0.0 {
                idx = i;
                break;
            }
            idx = i;
        }
        centroids.push(points[idx].clone());
        let c = centroids.last().unwrap();
        for (i, p) in points.iter().enumerate() {
            d2[i] = d2[i].min(1.0 - dot(p, c));
        }
    }
    let mut assign = vec![0usize; n];
    for _ in 0..iters {
        for (i, p) in points.iter().enumerate() {
            let mut best = 0;
            let mut best_s = f32::MIN;
            for (c, cen) in centroids.iter().enumerate() {
                let s = dot(p, cen);
                if s > best_s {
                    best_s = s;
                    best = c;
                }
            }
            assign[i] = best;
        }
        let mut sums = vec![vec![0f32; dim]; k];
        let mut counts = vec![0usize; k];
        for (i, p) in points.iter().enumerate() {
            counts[assign[i]] += 1;
            for d in 0..dim {
                sums[assign[i]][d] += p[d];
            }
        }
        for c in 0..k {
            if counts[c] == 0 {
                // re-seed empty cluster on a random point
                centroids[c] = points[rng.gen_range(0..n)].clone();
            } else {
                normalize(&mut sums[c]);
                centroids[c] = sums[c].clone();
            }
        }
    }
    (centroids.into_iter().flatten().collect(), assign)
}
