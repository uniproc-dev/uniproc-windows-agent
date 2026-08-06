mod enum_processes;
mod vars;

use anyhow::Result;
use crossbeam_channel::Sender;

use crate::providers::bootstrap::enum_processes::enum_processes;
use crate::providers::provider::{LivePids, Provider};
use crate::sink::Sink;

pub struct BootstrapProvider {
    enrich_tx: Option<Sender<u32>>,
}

impl BootstrapProvider {
    pub fn new(enrich_tx: Option<Sender<u32>>) -> Self {
        Self { enrich_tx }
    }
}

impl Default for BootstrapProvider {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Provider for BootstrapProvider {
    fn start(&self, _: LivePids, sink: Sink) -> Result<()> {
        let changes = unsafe { enum_processes()? };
        if let Some(tx) = &self.enrich_tx {
            for change in &changes {
                if let crate::state::events::StateChange::ProcessRundown(e) = change {
                    let _ = tx.send(e.pid);
                }
            }
        }
        sink.emit_all(changes);
        Ok(())
    }

    fn stop(&self) {}

    fn is_oneshot(&self) -> bool {
        true
    }
}
