mod enum_processes;
mod vars;

use anyhow::Result;

use crate::providers::provider::{LivePids, Provider};
use crate::sink::Sink;
use crate::providers::bootstrap::enum_processes::enum_processes;

pub struct BootstrapProvider;

impl BootstrapProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BootstrapProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for BootstrapProvider {
    fn start(&self, _: LivePids, sink: Sink) -> Result<()> {
        sink.emit_all(unsafe { enum_processes()? });
        Ok(())
    }

    fn stop(&self) {}

    fn is_oneshot(&self) -> bool {
        true
    }
}
