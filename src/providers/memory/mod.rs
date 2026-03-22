mod intrnl;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;

use crate::collector::provider::{ProcessMap, Provider};
use crate::collector::state::StateChange;
use crate::etw::kernel_session::KernelSessionRouter;
use crate::providers::memory::intrnl::MemoryPoller;

pub struct MemoryPollerProvider {
    poller: MemoryPoller,
    queue: Arc<Mutex<Vec<StateChange>>>,
}

impl MemoryPollerProvider {
    pub fn new(interval_ms: Arc<AtomicU64>) -> Self {
        Self {
            poller: MemoryPoller::new(interval_ms),
            queue: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Provider for MemoryPollerProvider {
    fn start(&self, processes: ProcessMap, _: Arc<KernelSessionRouter>) -> Result<()> {
        let queue = self.queue.clone();
        self.poller.start(processes, move |snap| {
            queue.lock().push(StateChange::Memory(snap));
        });
        Ok(())
    }

    fn stop(&self) {
        self.poller.stop();
    }

    fn drain(&self) -> Vec<StateChange> {
        std::mem::take(&mut *self.queue.lock())
    }
}

impl Default for MemoryPollerProvider {
    fn default() -> Self {
        Self::new(Arc::new(AtomicU64::new(1000)))
    }
}
