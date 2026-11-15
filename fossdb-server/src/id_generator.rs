use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic id allocator.
///
/// Id `0` is reserved as the "unassigned" sentinel that the insert helpers in
/// [`crate::db`] use to decide whether to allocate an id, so this type never
/// hands out `0`.
pub struct IdGenerator {
    counter: AtomicU64,
}

impl IdGenerator {
    pub fn new(start: u64) -> Self {
        Self {
            counter: AtomicU64::new(start.max(1)),
        }
    }

    /// Returns the next unused id.
    ///
    /// # Panics
    ///
    /// Panics if the id space is exhausted. `fetch_add` wraps silently rather
    /// than panicking, and a wrapped counter would start returning `0` — the
    /// "unassigned" sentinel — and then collide with every existing
    /// low-numbered record. Failing loudly is the lesser evil.
    pub fn next(&self) -> u64 {
        let id = self.counter.fetch_add(1, Ordering::SeqCst);
        assert!(
            id != 0 && id != u64::MAX,
            "id space exhausted; refusing to wrap and collide with existing records"
        );
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_sequentially_from_start() {
        let ids = IdGenerator::new(7);
        assert_eq!(ids.next(), 7);
        assert_eq!(ids.next(), 8);
        assert_eq!(ids.next(), 9);
    }

    #[test]
    fn never_returns_the_zero_sentinel() {
        let ids = IdGenerator::new(0);
        assert_eq!(ids.next(), 1);
    }

    #[test]
    #[should_panic(expected = "id space exhausted")]
    fn panics_instead_of_wrapping() {
        let ids = IdGenerator::new(u64::MAX);
        let _ = ids.next();
    }
}
