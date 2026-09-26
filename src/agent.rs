use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use futures::channel::oneshot;

use crate::api::{Command, CommandResult, Snapshot};
use crate::embedded::{Embedded, StartError};
use crate::remote::Remote;

/// The agent either way: running in this process or behind the service's pipe.
/// Both answer the same calls with the same `api` structs.
#[derive(Clone)]
pub enum Agent {
    Embedded(Arc<Embedded>),
    Remote(Remote),
}

impl Agent {
    /// Starts monitoring in this process; needs it elevated.
    pub fn embedded() -> Result<Self, StartError> {
        Ok(Self::Embedded(Arc::new(Embedded::start()?)))
    }

    /// Connects to the service, waiting up to `give_up_after` for its pipe.
    pub async fn remote(give_up_after: Duration) -> Result<Self> {
        Ok(Self::Remote(Remote::connect(give_up_after).await?))
    }

    /// Always answers in process; over the pipe it proves the session is alive.
    pub async fn ping(&self) -> Result<()> {
        match self {
            Self::Embedded(_) => Ok(()),
            Self::Remote(remote) => remote.ping().await,
        }
    }

    /// In process it is always there; over the pipe it is None when the
    /// process list kept changing under the metrics.
    pub async fn snapshot(&self) -> Result<Option<Snapshot>> {
        match self {
            Self::Embedded(agent) => Ok(Some(agent.snapshot())),
            Self::Remote(remote) => remote.snapshot().await,
        }
    }

    /// `None` leaves that interval as it is.
    pub async fn set_intervals(&self, memory: Option<Duration>, cpu: Option<Duration>) -> Result<()> {
        match self {
            Self::Embedded(agent) => {
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

    /// In process the command runs on a thread of its own, so awaiting it never blocks an executor.
    pub async fn run(&self, command: Command) -> Result<CommandResult> {
        match self {
            Self::Embedded(agent) => {
                let agent = agent.clone();
                let (tx, rx) = oneshot::channel();
                std::thread::Builder::new()
                    .name("agent-command".into())
                    .spawn(move || {
                        let _ = tx.send(agent.run(command));
                    })?;
                rx.await.map_err(|_| anyhow!("the command thread panicked"))
            }
            Self::Remote(remote) => remote.run(command).await,
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
        }
        let _ = calls;
    }

    #[test]
    fn the_agent_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Agent>();
    }
}
