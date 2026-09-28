use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_channel::{Receiver, Sender};

use crate::state::events::StateChange;

/// Channel capacity. What passes through is a disk and a network batch per
/// window; the process list is read by the tick and image verdicts come on
/// their own channel. A full channel degrades to counted drops instead of growth.
pub const DEFAULT_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct Sink {
    tx: Sender<StateChange>,
    dropped: Arc<AtomicU64>,
    wake: Arc<dyn Fn() + Send + Sync>,
    high_water: usize,
}

impl Sink {
    /// `wake` wakes whoever drains the channel when it is half full,
    /// instead of waiting for its period.
    pub fn bounded(capacity: usize, wake: impl Fn() + Send + Sync + 'static) -> (Self, Receiver<StateChange>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
                wake: Arc::new(wake),
                high_water: (capacity / 2).max(1),
            },
            rx,
        )
    }

    pub fn emit(&self, change: StateChange) {
        if self.tx.try_send(change).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        if self.tx.len() >= self.high_water {
            (self.wake)();
        }
    }

    pub fn emit_all(&self, changes: impl IntoIterator<Item = StateChange>) {
        for change in changes {
            self.emit(change);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn traffic() -> StateChange {
        StateChange::Network(Default::default())
    }

    fn parked() -> std::thread::JoinHandle<Duration> {
        std::thread::spawn(|| {
            let started = Instant::now();
            std::thread::park_timeout(Duration::from_secs(30));
            started.elapsed()
        })
    }

    #[test]
    fn a_half_full_channel_wakes_the_drainer() {
        let drainer = parked();
        let thread = drainer.thread().clone();
        let (sink, _rx) = Sink::bounded(4, move || thread.unpark());

        sink.emit(traffic());
        sink.emit(traffic());

        let parked = drainer.join().unwrap();
        assert!(parked < Duration::from_secs(5), "parked {parked:?}");
    }

    #[test]
    fn a_full_channel_counts_what_it_drops() {
        let (sink, _rx) = Sink::bounded(1, || {});
        sink.emit(traffic());
        sink.emit(traffic());
        assert_eq!(sink.dropped(), 1);
    }
}
