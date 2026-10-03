use crate::etw::router::KernelRouterBuilder;
use crate::report::SessionHealth;
use crate::sink::Sink;

pub trait Provider: Send + Sync {
    fn register(&self, _builder: &mut KernelRouterBuilder) -> anyhow::Result<()> {
        Ok(())
    }
    fn start(&self, _sink: Sink) -> anyhow::Result<()> {
        Ok(())
    }
    /// The sessions as ETW counts them, about once a second.
    fn health(&self, _sessions: &[SessionHealth]) {}
    fn stop(&self);
}
