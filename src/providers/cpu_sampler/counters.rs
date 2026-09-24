use std::time::{Duration, Instant};

use fxhash::FxHashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SampleKey {
    pub tid: u32,
    pub pid_hint: u32,
}

pub type Samples = FxHashMap<SampleKey, u64>;

/// Samples counted on the ETW pump thread, owned by it alone, and handed over
/// whole once enough have gathered or enough time has passed.
pub struct SampleBatch {
    counts: Samples,
    events: usize,
    since: Instant,
    max_entries: usize,
    max_events: usize,
    max_age: Duration,
}

impl SampleBatch {
    pub fn new(max_entries: usize, max_events: usize, max_age: Duration) -> Self {
        Self {
            counts: Samples::default(),
            events: 0,
            since: Instant::now(),
            max_entries,
            max_events,
            max_age,
        }
    }

    pub fn record(&mut self, key: SampleKey, count: u64, now: Instant) -> Option<Samples> {
        *self.counts.entry(key).or_default() += count;
        self.events += 1;

        let due = self.events >= self.max_events
            || self.counts.len() >= self.max_entries
            || now.duration_since(self.since) >= self.max_age;
        if !due {
            return None;
        }

        self.events = 0;
        self.since = now;
        let capacity = self.counts.len();
        Some(std::mem::replace(
            &mut self.counts,
            Samples::with_capacity_and_hasher(capacity, Default::default()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tid: u32) -> SampleKey {
        SampleKey { tid, pid_hint: 0 }
    }

    fn batch() -> SampleBatch {
        SampleBatch::new(100, 100, Duration::from_secs(3600))
    }

    #[test]
    fn counts_for_the_same_thread_accumulate_until_handed_over() {
        let mut b = SampleBatch::new(100, 3, Duration::from_secs(3600));
        let now = Instant::now();
        assert!(b.record(key(1), 3, now).is_none());
        assert!(b.record(key(1), 4, now).is_none());

        let handed = b.record(key(2), 1, now).expect("the third event is due");
        assert_eq!(handed.get(&key(1)).copied(), Some(7));
        assert_eq!(handed.get(&key(2)).copied(), Some(1));
    }

    #[test]
    fn a_handover_leaves_the_next_batch_empty() {
        let mut b = SampleBatch::new(100, 2, Duration::from_secs(3600));
        let now = Instant::now();
        b.record(key(1), 1, now);
        b.record(key(1), 1, now).expect("due");

        let next = b.record(key(2), 1, now);
        assert!(next.is_none());
        let next = b.record(key(2), 1, now).expect("due again");
        assert_eq!(next.len(), 1, "nothing from the first batch is left over");
    }

    #[test]
    fn too_many_threads_hand_over_early() {
        let mut b = SampleBatch::new(2, 100, Duration::from_secs(3600));
        let now = Instant::now();
        assert!(b.record(key(1), 1, now).is_none());
        assert!(b.record(key(2), 1, now).is_some());
    }

    #[test]
    fn an_old_batch_is_handed_over_even_when_small() {
        let mut b = batch();
        let start = Instant::now();
        assert!(b.record(key(1), 1, start).is_none());
        assert!(b.record(key(1), 1, start + Duration::from_secs(3601)).is_some());
    }
}
