//! Service seniority: the number of days (within the last 365) during which a node answered at
//! least 90 % of its challenges. Non-transferable, impossible to accelerate.

use std::collections::{BTreeMap, HashMap};

use alp_grid_core::keys::PublicKey;
use alp_grid_core::params::{SERVICE_DAY_MIN_SUCCESS, SERVICE_SENIORITY_WINDOW_DAYS};
use alp_grid_core::time::DAY;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DayRecord {
    pub ok: u32,
    pub total: u32,
}

impl DayRecord {
    pub fn earned(&self) -> bool {
        self.total > 0 && (self.ok as f32 / self.total as f32) >= SERVICE_DAY_MIN_SUCCESS
    }
}

/// Challenge history of one node, by day number (unix days).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub days: BTreeMap<u64, DayRecord>,
    pub first_seen: Option<u64>,
}

impl ServiceRecord {
    pub fn record(&mut self, now: u64, ok: bool) {
        let d = now / DAY;
        let r = self.days.entry(d).or_default();
        r.total += 1;
        if ok {
            r.ok += 1;
        }
        if self.first_seen.is_none() {
            self.first_seen = Some(now);
        }
    }

    /// Earned days within the window ending at `now`.
    pub fn seniority(&self, now: u64) -> u32 {
        let today = now / DAY;
        let from = today.saturating_sub(SERVICE_SENIORITY_WINDOW_DAYS);
        self.days.range(from..=today).filter(|(_, r)| r.earned()).count() as u32
    }

    pub fn prune(&mut self, now: u64) {
        let from = (now / DAY).saturating_sub(SERVICE_SENIORITY_WINDOW_DAYS + 1);
        self.days = self.days.split_off(&from);
    }

    pub fn success_ratio(&self) -> f32 {
        let (ok, total) = self.days.values().fold((0u32, 0u32), |(a, b), r| (a + r.ok, b + r.total));
        if total == 0 {
            0.0
        } else {
            ok as f32 / total as f32
        }
    }
}

/// Everything this node knows about the service of others.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceBook {
    pub records: HashMap<PublicKey, ServiceRecord>,
}

impl ServiceBook {
    pub fn record(&mut self, peer: PublicKey, now: u64, ok: bool) {
        self.records.entry(peer).or_default().record(now, ok);
    }
    pub fn seniority(&self, peer: &PublicKey, now: u64) -> u32 {
        self.records.get(peer).map(|r| r.seniority(now)).unwrap_or(0)
    }
    /// Weight in [0, 1] used by routing and guardian ordering: 0 for a newcomer, 1 after a year.
    pub fn weight(&self, peer: &PublicKey, now: u64) -> f32 {
        (self.seniority(peer, now) as f32 / SERVICE_SENIORITY_WINDOW_DAYS as f32).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seniority_counts_good_days_only() {
        let mut r = ServiceRecord::default();
        let t0 = 1_800_000_000;
        for d in 0..10u64 {
            for i in 0..10 {
                // day 3 is bad: 5/10
                let ok = !(d == 3 && i % 2 == 0);
                r.record(t0 + d * DAY + i, ok);
            }
        }
        assert_eq!(r.seniority(t0 + 9 * DAY), 9);
        // a sybil that just appeared has zero
        let fresh = ServiceRecord::default();
        assert_eq!(fresh.seniority(t0), 0);
        // outside the window, days vanish
        assert_eq!(r.seniority(t0 + 400 * DAY), 0);
    }
}
