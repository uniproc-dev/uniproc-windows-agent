use crate::collector::state::{ProcessEntry, StateChange};
use crate::etw::kernel_session::KernelSessionRouter;
use dashmap::DashMap;
use std::sync::Arc;

pub type ProcessMap = Arc<DashMap<u32, ProcessEntry>>;

pub trait Provider: Send + Sync {
    fn start(
        &self,
        processes: ProcessMap,
        kernel_session: Arc<KernelSessionRouter>,
    ) -> anyhow::Result<()>;
    fn stop(&self);
    fn drain(&self) -> Vec<StateChange>;
    fn is_oneshot(&self) -> bool {
        false
    }
}
