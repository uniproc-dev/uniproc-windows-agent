use std::sync::Arc;

use dashmap::DashMap;

use crate::etw::router::KernelRouterBuilder;
use crate::sink::Sink;

/// Running processes, each with the generation of the start that put it
/// there: a pid reused by a new process comes back with a new generation.
pub type LivePids = Arc<DashMap<u32, u64>>;

pub trait Provider: Send + Sync {
    fn register(&self, _builder: &mut KernelRouterBuilder) -> anyhow::Result<()> {
        Ok(())
    }
    fn start(&self, _live_pids: LivePids, _sink: Sink) -> anyhow::Result<()> {
        Ok(())
    }
    fn stop(&self);
    fn is_oneshot(&self) -> bool {
        false
    }
}
