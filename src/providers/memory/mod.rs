mod intrnl;
mod vars;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::Result;

use crate::providers::provider::{LivePids, Provider};
use crate::sink::Sink;
use crate::state::events::StateChange;
use crate::providers::memory::intrnl::MemoryPoller;

pub struct MemoryPollerProvider {
    poller: MemoryPoller,
}

impl MemoryPollerProvider {
    pub fn new(interval_ms: Arc<AtomicU64>) -> Self {
        Self {
            poller: MemoryPoller::new(interval_ms),
        }
    }
}

impl Provider for MemoryPollerProvider {
    fn start(&self, live_pids: LivePids, sink: Sink) -> Result<()> {
        self.poller.start(live_pids, move |snap| {
            sink.emit(StateChange::Memory(snap));
        });
        Ok(())
    }

    fn stop(&self) {
        self.poller.stop();
    }
}

impl Default for MemoryPollerProvider {
    fn default() -> Self {
        Self::new(Arc::new(AtomicU64::new(crate::settings::DEFAULT_INTERVAL_MS)))
    }
}
