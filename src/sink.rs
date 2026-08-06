use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

impl Sink {
    pub fn bounded(capacity: usize) -> (Self, Receiver<StateChange>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    pub fn emit(&self, change: StateChange) {
        if self.tx.try_send(change).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
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
