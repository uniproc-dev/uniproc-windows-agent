use fxhash::FxHashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SampleKey {
    pub tid: u32,
    pub pid_hint: u32,
}

pub type Samples = FxHashMap<SampleKey, u64>;

/// Samples counted on the ETW pump thread, owned by it alone, and handed over
/// whole once enough have gathered or enough time has passed. Time is the
/// events' own timestamps, in whatever ticks the caller measures `max_age` in.
pub struct SampleBatch {
    counts: Samples,
    events: usize,
    since: Option<i64>,
    max_entries: usize,
    max_events: usize,
    max_age: i64,
}

impl SampleBatch {
    pub fn new(max_entries: usize, max_events: usize, max_age: i64) -> Self {
        Self {
            counts: Samples::default(),
            events: 0,
            since: None,
            max_entries,
            max_events,
            max_age,
        }
    }

    pub fn record(&mut self, key: SampleKey, count: u64, now: i64) -> Option<Samples> {
        *self.counts.entry(key).or_default() += count;
        self.events += 1;
        let since = *self.since.get_or_insert(now);

        let due = self.events >= self.max_events
            || self.counts.len() >= self.max_entries
            || now - since >= self.max_age;
        if !due {
            return None;
        }

        self.events = 0;
        self.since = Some(now);
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

    const HOUR: i64 = 3600;

    fn batch() -> SampleBatch {
        SampleBatch::new(100, 100, HOUR)
    }

    #[test]
    fn counts_for_the_same_thread_accumulate_until_handed_over() {
        let mut b = SampleBatch::new(100, 3, HOUR);
        let now = 7;
        assert!(b.record(key(1), 3, now).is_none());
        assert!(b.record(key(1), 4, now).is_none());

        let handed = b.record(key(2), 1, now).expect("the third event is due");
        assert_eq!(handed.get(&key(1)).copied(), Some(7));
        assert_eq!(handed.get(&key(2)).copied(), Some(1));
    }

    #[test]
    fn a_handover_leaves_the_next_batch_empty() {
        let mut b = SampleBatch::new(100, 2, HOUR);
        let now = 7;
        b.record(key(1), 1, now);
        b.record(key(1), 1, now).expect("due");

        let next = b.record(key(2), 1, now);
        assert!(next.is_none());
        let next = b.record(key(2), 1, now).expect("due again");
        assert_eq!(next.len(), 1, "nothing from the first batch is left over");
    }

    #[test]
    fn too_many_threads_hand_over_early() {
        let mut b = SampleBatch::new(2, 100, HOUR);
        let now = 7;
        assert!(b.record(key(1), 1, now).is_none());
        assert!(b.record(key(2), 1, now).is_some());
    }

    #[test]
    fn an_old_batch_is_handed_over_even_when_small() {
        let mut b = batch();
        let start = 1_000;
        assert!(b.record(key(1), 1, start).is_none());
        assert!(b.record(key(1), 1, start + HOUR - 1).is_none());
        assert!(b.record(key(1), 1, start + HOUR).is_some());
    }

    #[test]
    fn the_age_counts_from_the_first_sample_not_from_zero() {
        let mut b = batch();
        assert!(
            b.record(key(1), 1, 10 * HOUR).is_none(),
            "a large first timestamp alone must not look like an old batch"
        );
    }
}
