use crate::etw::router::KernelRouterBuilder;
use crate::sink::Sink;

pub trait Provider: Send + Sync {
    fn register(&self, _builder: &mut KernelRouterBuilder) -> anyhow::Result<()> {
        Ok(())
    }
    fn start(&self, _sink: Sink) -> anyhow::Result<()> {
        Ok(())
    }
    fn stop(&self);
}
