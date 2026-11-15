//! Last-seen tracking for API keys.
//!
//! Records when each key last authenticated a request. This is deliberately
//! in memory rather than in the database: workers poll continuously, and
//! persisting a timestamp per request would turn every poll into a write
//! transaction against the same record.
//!
//! The consequence is that activity resets when the server restarts, which
//! the admin output states explicitly rather than presenting a restarted
//! server as a fleet of idle collectors.
//!
//! Now that each collector and worker carries its own named key, this is what
//! makes `fossdb admin collectors` and `fossdb admin workers` report real
//! per-instance liveness. It still counts *keys*, not processes: two workers
//! sharing one key are indistinguishable, which is a reason to issue one key
//! per host.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

#[derive(Debug, Default)]
pub struct KeyActivity {
    last_seen: HashMap<String, DateTime<Utc>>,
}

impl KeyActivity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note that `key_id` just authenticated a request.
    ///
    /// Bounded by the number of API keys that exist, which only an
    /// administrator can grow, so this needs no eviction policy.
    pub fn record(&mut self, key_id: &str, now: DateTime<Utc>) {
        self.last_seen.insert(key_id.to_string(), now);
    }

    pub fn last_seen(&self, key_id: &str) -> Option<DateTime<Utc>> {
        self.last_seen.get(key_id).copied()
    }

    /// Drop the entry for a key, used when a key is revoked.
    pub fn forget(&mut self, key_id: &str) {
        self.last_seen.remove(key_id);
    }

    pub fn len(&self) -> usize {
        self.last_seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.last_seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn records_and_reads_back() {
        let mut activity = KeyActivity::new();
        let now = Utc::now();

        assert_eq!(activity.last_seen("4m7k2xqa"), None);

        activity.record("4m7k2xqa", now);
        assert_eq!(activity.last_seen("4m7k2xqa"), Some(now));
    }

    #[test]
    fn later_observations_win() {
        let mut activity = KeyActivity::new();
        let first = Utc::now() - Duration::minutes(5);
        let second = Utc::now();

        activity.record("4m7k2xqa", first);
        activity.record("4m7k2xqa", second);

        assert_eq!(activity.last_seen("4m7k2xqa"), Some(second));
        assert_eq!(activity.len(), 1);
    }

    #[test]
    fn tracks_keys_independently() {
        let mut activity = KeyActivity::new();
        let now = Utc::now();

        activity.record("collector", now);
        activity.record("worker00", now);

        assert_eq!(activity.len(), 2);
        assert!(activity.last_seen("collector").is_some());
        assert!(activity.last_seen("worker00").is_some());
        assert!(activity.last_seen("missing0").is_none());
    }

    #[test]
    fn forget_removes_a_revoked_key() {
        let mut activity = KeyActivity::new();
        activity.record("4m7k2xqa", Utc::now());

        activity.forget("4m7k2xqa");
        assert!(activity.last_seen("4m7k2xqa").is_none());
        assert!(activity.is_empty());

        // Forgetting an unknown key is a no-op, not a panic.
        activity.forget("nosuchky");
    }
}
