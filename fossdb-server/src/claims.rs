use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a worker may hold a claim on a version before it is treated as
/// abandoned.
///
/// A worker that crashes, is killed, or fails mid-analysis never calls
/// `submit_analysis`. Without an expiry its claim would block that version from
/// ever being analyzed again for the lifetime of the server process.
pub const CLAIM_TTL: Duration = Duration::from_secs(30 * 60);

/// Tracks which package versions are currently being analyzed, so two workers
/// are not handed the same task.
///
/// Claims expire after [`CLAIM_TTL`], which both frees abandoned work and keeps
/// the map from growing without bound as failed tasks accumulate.
#[derive(Debug, Default)]
pub struct ClaimSet {
    claims: HashMap<u64, Instant>,
}

impl ClaimSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claims `version_id` unless a non-expired claim already exists.
    ///
    /// Returns `true` if the claim was granted.
    pub fn try_claim(&mut self, version_id: u64, now: Instant) -> bool {
        match self.claims.get(&version_id) {
            Some(claimed_at) if now.saturating_duration_since(*claimed_at) < CLAIM_TTL => false,
            _ => {
                self.claims.insert(version_id, now);
                true
            }
        }
    }

    /// Drops a claim once its analysis has been durably stored.
    pub fn release(&mut self, version_id: u64) {
        self.claims.remove(&version_id);
    }

    /// Removes every claim whose TTL has elapsed.
    pub fn prune_expired(&mut self, now: Instant) {
        self.claims
            .retain(|_, claimed_at| now.saturating_duration_since(*claimed_at) < CLAIM_TTL);
    }

    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Iterate live claims as `(version_id, claimed_at)`.
    ///
    /// Used by the admin socket to report in-flight work. Note this may
    /// include claims that have expired but not yet been pruned, so callers
    /// that care should compare against [`CLAIM_TTL`].
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &Instant)> {
        self.claims.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_a_free_claim_and_refuses_a_live_duplicate() {
        let mut claims = ClaimSet::new();
        let t0 = Instant::now();
        assert!(claims.try_claim(1, t0));
        assert!(!claims.try_claim(1, t0), "second worker must not get the same version");
        assert!(claims.try_claim(2, t0), "a different version is unaffected");
    }

    #[test]
    fn expired_claim_is_reissued() {
        let mut claims = ClaimSet::new();
        let t0 = Instant::now();
        assert!(claims.try_claim(1, t0));

        let later = t0 + CLAIM_TTL + Duration::from_secs(1);
        assert!(
            claims.try_claim(1, later),
            "an abandoned claim must become available again"
        );
    }

    #[test]
    fn release_frees_immediately() {
        let mut claims = ClaimSet::new();
        let t0 = Instant::now();
        assert!(claims.try_claim(1, t0));
        claims.release(1);
        assert!(claims.try_claim(1, t0));
    }

    #[test]
    fn prune_drops_only_expired_entries() {
        let mut claims = ClaimSet::new();
        let t0 = Instant::now();
        claims.try_claim(1, t0);

        let later = t0 + CLAIM_TTL - Duration::from_secs(1);
        claims.try_claim(2, later);
        claims.prune_expired(later);
        assert_eq!(claims.len(), 2, "neither claim has expired yet");

        let much_later = t0 + CLAIM_TTL + Duration::from_secs(1);
        claims.prune_expired(much_later);
        assert_eq!(claims.len(), 1, "only the older claim should be dropped");
        assert!(!claims.try_claim(2, much_later), "claim 2 is still live");
    }

    #[test]
    fn releasing_an_unheld_claim_is_a_noop() {
        let mut claims = ClaimSet::new();
        claims.release(42);
        assert!(claims.is_empty());
    }
}
