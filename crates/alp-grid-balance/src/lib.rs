//! Storage balancing. We balance the *fill ratio*, not raw bytes: above 80 % a node refuses new
//! copies and the next-closest node takes them. Big servers carry several identities (virtual
//! nodes), each with its own service seniority. Overfull nodes migrate slowly to emptier ones.

use alp_grid_core::params::OVERFLOW_FILL_RATIO;
use serde::{Deserialize, Serialize};

/// Bytes one virtual node identity represents. A 1 TiB server runs 16 identities.
pub const VIRTUAL_NODE_UNIT: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_VIRTUAL_NODES: u64 = 64;
/// Soft migration rate limit, bytes per second.
pub const MIGRATION_RATE_BPS: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Capacity {
    pub declared_bytes: u64,
    pub used_bytes: u64,
}

impl Capacity {
    pub fn fill(&self) -> f32 {
        if self.declared_bytes == 0 {
            1.0
        } else {
            (self.used_bytes as f64 / self.declared_bytes as f64) as f32
        }
    }
    pub fn accepts_new(&self) -> bool {
        self.fill() < OVERFLOW_FILL_RATIO
    }
    pub fn virtual_nodes(&self) -> u64 {
        (self.declared_bytes / VIRTUAL_NODE_UNIT).clamp(1, MAX_VIRTUAL_NODES)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MigrationStep {
    pub from: usize,
    pub to: usize,
    pub bytes: u64,
}

/// Plan transfers from nodes above the overflow threshold to the emptiest nodes, within
/// `budget_bytes` for this tick. Indices refer to the input slice.
pub fn plan_migration(nodes: &[Capacity], budget_bytes: u64) -> Vec<MigrationStep> {
    let mut over: Vec<(usize, u64)> = nodes
        .iter()
        .enumerate()
        .filter(|(_, c)| c.fill() >= OVERFLOW_FILL_RATIO)
        .map(|(i, c)| {
            (
                i,
                c.used_bytes
                    .saturating_sub((c.declared_bytes as f64 * (OVERFLOW_FILL_RATIO as f64 - 0.05)) as u64),
            )
        })
        .collect();
    over.sort_by_key(|x| std::cmp::Reverse(x.1));
    let mut under: Vec<(usize, f32)> = nodes.iter().enumerate().filter(|(_, c)| c.fill() < 0.5).map(|(i, c)| (i, c.fill())).collect();
    under.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut steps = Vec::new();
    let mut budget = budget_bytes;
    for (from, excess) in over {
        if budget == 0 {
            break;
        }
        for (to, _) in &under {
            if budget == 0 {
                break;
            }
            let room = nodes[*to].declared_bytes / 2 - nodes[*to].used_bytes.min(nodes[*to].declared_bytes / 2);
            let bytes = excess.min(room).min(budget);
            if bytes > 0 {
                steps.push(MigrationStep { from, to: *to, bytes });
                budget -= bytes;
            }
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_and_virtual_nodes() {
        let c = Capacity {
            declared_bytes: 100,
            used_bytes: 85,
        };
        assert!(!c.accepts_new());
        assert!(Capacity {
            declared_bytes: 100,
            used_bytes: 10
        }
        .accepts_new());
        assert_eq!(
            Capacity {
                declared_bytes: 1 << 40,
                used_bytes: 0
            }
            .virtual_nodes(),
            16
        );
        assert_eq!(
            Capacity {
                declared_bytes: 1 << 30,
                used_bytes: 0
            }
            .virtual_nodes(),
            1
        );
    }

    #[test]
    fn migration_moves_from_full_to_empty() {
        let nodes = vec![
            Capacity {
                declared_bytes: 1000,
                used_bytes: 900,
            },
            Capacity {
                declared_bytes: 1000,
                used_bytes: 100,
            },
            Capacity {
                declared_bytes: 1000,
                used_bytes: 600,
            },
        ];
        let plan = plan_migration(&nodes, 10_000);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].from, 0);
        assert_eq!(plan[0].to, 1);
        assert!(plan[0].bytes <= 400);
        assert!(plan_migration(&nodes, 50)[0].bytes == 50);
    }
}
