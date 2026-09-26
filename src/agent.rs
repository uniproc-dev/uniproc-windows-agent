use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::api::{Command, CommandResult, ServiceStatus, Snapshot};
use crate::local::{Local, StartError};
use crate::remote::Remote;

/// The agent either way: running in this process or behind the service's pipe.
/// Both answer the same calls with the same `api` structs.
#[derive(Clone)]
pub enum Agent {
    Local(Arc<Local>),
    Remote(Remote),
}

impl Agent {
    /// Starts monitoring in this process; needs it elevated.
    pub fn local() -> Result<Self, StartError> {
        Ok(Self::Local(Arc::new(Local::start()?)))
    }

    /// Connects to the service, waiting up to `give_up_after` for its pipe.
    pub async fn remote(give_up_after: Duration) -> Result<Self> {
        Ok(Self::Remote(Remote::connect(give_up_after).await?))
    }

    /// Always answers in process; over the pipe it proves the session is alive.
    pub async fn ping(&self) -> Result<()> {
        match self {
            Self::Local(_) => Ok(()),
            Self::Remote(remote) => remote.ping().await,
        }
    }

    /// In process it is always there; over the pipe it is None when the
    /// process list kept changing under the metrics.
    pub async fn snapshot(&self) -> Result<Option<Snapshot>> {
        match self {
            Self::Local(agent) => Ok(Some(agent.snapshot())),
            Self::Remote(remote) => remote.snapshot().await,
        }
    }

    /// `None` leaves that interval as it is.
    pub async fn set_intervals(&self, memory: Option<Duration>, cpu: Option<Duration>) -> Result<()> {
        match self {
            Self::Local(agent) => {
                if let Some(memory) = memory {
                    agent.set_memory_interval(memory);
                }
                if let Some(cpu) = cpu {
                    agent.set_cpu_interval(cpu);
                }
                Ok(())
            }
            Self::Remote(remote) => remote.set_intervals(memory, cpu).await,
        }
    }

    /// Awaiting it never blocks an executor: in process the command runs on the agent's own threads.
    pub async fn run(&self, command: Command) -> Result<CommandResult> {
        match self {
            Self::Local(agent) => agent.run(command).await,
            Self::Remote(remote) => remote.run(command).await,
        }
    }

    /// The service's status now, then every change until the stream is dropped.
    /// Ends when the service is gone, cannot be opened, monitoring stops, or the session ends.
    pub async fn watch_service(&self, name: &str) -> Result<BoxStream<'static, ServiceStatus>> {
        match self {
            Self::Local(agent) => Ok(agent.watch_service(name).boxed()),
            Self::Remote(remote) => Ok(remote.watch_service(name).await?.boxed()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send<T: Send>(_: T) {}

    #[test]
    fn every_call_can_be_awaited_on_any_executor() {
        fn calls(agent: &Agent) {
            send(agent.ping());
            send(agent.snapshot());
            send(agent.set_intervals(None, None));
            send(agent.run(Command::Kill { pid: 0 }));
            send(agent.watch_service("svc"));
        }
        let _ = calls;
    }

    #[test]
    fn the_agent_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Agent>();
    }
}
