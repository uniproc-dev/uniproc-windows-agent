use std::sync::Arc;

use dashmap::DashSet;

use crate::etw::router::KernelRouterBuilder;
use crate::sink::Sink;

pub type LivePids = Arc<DashSet<u32>>;

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
