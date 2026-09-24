mod intrnl;
mod vars;

use std::sync::Arc;

use anyhow::Result;

use crate::providers::provider::{LivePids, Provider};
use crate::settings::{IDLE_MEMORY_INTERVAL_MS, PollInterval};
use crate::sink::Sink;
use crate::state::events::StateChange;
use crate::providers::memory::intrnl::MemoryPoller;

pub struct MemoryPollerProvider {
    poller: MemoryPoller,
}

impl MemoryPollerProvider {
    pub fn new(interval: Arc<PollInterval>) -> Self {
        Self {
            poller: MemoryPoller::new(interval),
        }
    }
}

impl Provider for MemoryPollerProvider {
    fn start(&self, live_pids: LivePids, sink: Sink) -> Result<()> {
        self.poller.start(live_pids, move |snaps| {
            sink.emit(StateChange::Memory(snaps));
        });
        Ok(())
    }

    fn stop(&self) {
        self.poller.stop();
    }
}

impl Default for MemoryPollerProvider {
    fn default() -> Self {
        Self::new(Arc::new(PollInterval::new(IDLE_MEMORY_INTERVAL_MS)))
    }
}
