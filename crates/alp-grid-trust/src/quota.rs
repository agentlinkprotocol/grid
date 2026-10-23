//! Publication quota of an operator, from proven contribution.
//! quota = base + 5 agents per earned service day + 50 agents per GiB proven served,
//! capped during the 30-day trial period.

use alp_grid_core::params::{BASE_QUOTA_AGENTS, TRIAL_PERIOD};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Contribution {
    /// Sum of seniority days of the operator's nodes.
    pub seniority_days: u32,
    /// Bytes this operator demonstrably stores for others (from storage challenges).
    pub proven_bytes: u64,
    /// When the operator's first node appeared.
    pub first_seen: u64,
}

pub fn quota_agents(c: &Contribution, now: u64) -> u64 {
    let gib = c.proven_bytes / (1024 * 1024 * 1024);
    let earned = BASE_QUOTA_AGENTS + 5 * c.seniority_days as u64 + 50 * gib;
    let in_trial = now < c.first_seen.saturating_add(TRIAL_PERIOD);
    if in_trial {
        // ramps linearly from base to base + 150 across the trial
        let elapsed = now.saturating_sub(c.first_seen) as f64 / TRIAL_PERIOD as f64;
        let cap = BASE_QUOTA_AGENTS + (150.0 * elapsed.clamp(0.0, 1.0)) as u64;
        earned.min(cap)
    } else {
        earned
    }
}

pub fn can_publish(c: &Contribution, now: u64, current_agents: u64) -> bool {
    current_agents < quota_agents(c, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alp_grid_core::time::DAY;

    #[test]
    fn newcomer_gets_base_then_ramps() {
        let t0 = 1_800_000_000;
        let c = Contribution {
            seniority_days: 0,
            proven_bytes: 0,
            first_seen: t0,
        };
        assert_eq!(quota_agents(&c, t0), BASE_QUOTA_AGENTS);
        let c2 = Contribution {
            seniority_days: 15,
            proven_bytes: 10 << 30,
            first_seen: t0,
        };
        let q = quota_agents(&c2, t0 + 15 * DAY);
        assert!(q > BASE_QUOTA_AGENTS && q <= BASE_QUOTA_AGENTS + 150);
        let q3 = quota_agents(&c2, t0 + 40 * DAY);
        assert_eq!(q3, 10 + 75 + 500);
        assert!(can_publish(&c, t0, 9));
        assert!(!can_publish(&c, t0, 10));
    }
}
