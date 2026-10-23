//! Unix time helpers. All Atlas timestamps are unsigned seconds since the Unix epoch.

pub const SECOND: u64 = 1;
pub const MINUTE: u64 = 60;
pub const HOUR: u64 = 3600;
pub const DAY: u64 = 86_400;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
