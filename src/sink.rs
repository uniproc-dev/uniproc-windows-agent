use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::Thread;

use crossbeam_channel::{Receiver, Sender};

use crate::state::events::StateChange;

/// Channel capacity. Sized for the bootstrap rundown (~400 processes with
/// ~8k threads in one burst) with 2x headroom; a full channel degrades to
/// counted drops instead of growth. 65k slots cost 8 MB resident for no
/// benefit, so keep it tight.
pub const DEFAULT_CAPACITY: usize = 16_384;

#[derive(Clone)]
pub struct Sink {
    tx: Sender<StateChange>,
    dropped: Arc<AtomicU64>,
    drainer: Arc<OnceLock<Thread>>,
    high_water: usize,
}

impl Sink {
    pub fn bounded(capacity: usize) -> (Self, Receiver<StateChange>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
                drainer: Arc::new(OnceLock::new()),
                high_water: (capacity / 2).max(1),
            },
            rx,
        )
    }

    /// The thread that drains the channel between requests; it is woken as
    /// soon as a process starts or the channel is half full, instead of
    /// waiting for its period.
    pub fn set_drainer(&self, thread: Thread) {
        let _ = self.drainer.set(thread);
    }

    pub fn emit(&self, change: StateChange) {
        let started = matches!(change, StateChange::ProcessStarted(_));
        if self.tx.try_send(change).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        if (started || self.tx.len() >= self.high_water)
            && let Some(drainer) = self.drainer.get()
        {
            drainer.unpark();
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

    #[test]
    fn a_half_full_channel_wakes_the_drainer() {
        let (sink, _rx) = Sink::bounded(4);
        let drainer = std::thread::spawn(|| {
            let started = Instant::now();
            std::thread::park_timeout(Duration::from_secs(30));
            started.elapsed()
        });
        sink.set_drainer(drainer.thread().clone());

        sink.emit(StateChange::ProcessStopped(1));
        sink.emit(StateChange::ProcessStopped(2));

        let parked = drainer.join().unwrap();
        assert!(parked < Duration::from_secs(5), "parked {parked:?}");
    }

    #[test]
    fn a_process_start_wakes_the_drainer_at_once() {
        let (sink, _rx) = Sink::bounded(1024);
        let drainer = std::thread::spawn(|| {
            let started = Instant::now();
            std::thread::park_timeout(Duration::from_secs(30));
            started.elapsed()
        });
        sink.set_drainer(drainer.thread().clone());

        sink.emit(StateChange::ProcessStarted(Box::default()));

        let parked = drainer.join().unwrap();
        assert!(parked < Duration::from_secs(5), "parked {parked:?}");
    }

    #[test]
    fn a_full_channel_counts_what_it_drops() {
        let (sink, _rx) = Sink::bounded(1);
        sink.emit(StateChange::ProcessStopped(1));
        sink.emit(StateChange::ProcessStopped(2));
        assert_eq!(sink.dropped(), 1);
    }
}
