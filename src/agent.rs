use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::api::{Command, CommandResult, MetricSpec, ProcessEventBatch, Sample, ServiceStatus, Snapshot, Update};
use crate::local::{Local, LocalProcessEvents, LocalSampler, LocalWatch, StartError};
use crate::remote::{Remote, RemoteProcessEvents, RemoteSampler, RemoteWatch};

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

    /// Services, processes and their states. In process it is always there;
    /// over the pipe it is None when the process list kept changing under the states.
    pub async fn snapshot(&self) -> Result<Option<Snapshot>> {
        match self {
            Self::Local(agent) => Ok(Some(agent.snapshot())),
            Self::Remote(remote) => remote.snapshot().await,
        }
    }

    /// Samples what `spec` asks for until the sampler is dropped.
    pub async fn subscribe(&self, spec: MetricSpec) -> Result<Sampler> {
        let inner = match self {
            Self::Local(agent) => Inner::Local(agent.subscribe(spec)),
            Self::Remote(remote) => Inner::Remote(remote.subscribe(spec).await?),
        };
        Ok(Sampler { inner, last: 0 })
    }

    /// Pushes every sample `spec` is due, with the lists it was taken against
    /// and what moved in them, until the watch is dropped.
    pub async fn watch(&self, spec: MetricSpec) -> Result<Watch> {
        Ok(match self {
            Self::Local(agent) => Watch::Local(agent.watch(spec)),
            Self::Remote(remote) => Watch::Remote(remote.watch(spec).await?),
        })
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

    /// The process starts and exits held, about the last hour, then each
    /// one as it happens, until the watch is dropped. An agent behind the
    /// pipe older than windows 2.8 is refused here, before anything is sent.
    pub async fn watch_process_events(&self) -> Result<ProcessEvents> {
        Ok(match self {
            Self::Local(agent) => ProcessEvents::Local(agent.watch_process_events()),
            Self::Remote(remote) => ProcessEvents::Remote(remote.watch_process_events().await?),
        })
    }
}

/// One subscription; the agent stops sampling for it when it is dropped.
pub struct Sampler {
    inner: Inner,
    last: u64,
}

enum Inner {
    Local(LocalSampler),
    Remote(RemoteSampler),
}

impl Sampler {
    /// The first call answers with the latest sample; every later one waits
    /// for the next, paced at the subscription's interval. Over the pipe an
    /// error means the session is gone.
    pub async fn next(&mut self) -> Result<Sample> {
        let sample = match &self.inner {
            Inner::Local(sampler) => sampler.sample(self.last).await,
            Inner::Remote(sampler) => sampler.sample(self.last).await?,
        };
        self.last = sample.snapshot;
        Ok(sample)
    }
}

/// One watch; the agent stops pushing to it when it is dropped.
pub enum Watch {
    Local(LocalWatch),
    Remote(RemoteWatch),
}

impl Watch {
    /// The next update; the first carries everything. Paced at the spec's
    /// interval. Over the pipe an error means the watch is over: the agent
    /// stopped or the session ended; watch again.
    pub async fn next(&mut self) -> Result<Update> {
        match self {
            Self::Local(watch) => Ok(watch.next().await),
            Self::Remote(watch) => watch.next().await,
        }
    }
}

/// The process starts and exits; the agent stops telling them when it is dropped.
pub enum ProcessEvents {
    Local(LocalProcessEvents),
    Remote(RemoteProcessEvents),
}

impl ProcessEvents {
    /// The next batch; the first carries `history_from` and the replay of
    /// about the last hour. An error means the watch is over: the agent
    /// stopped or the session ended; watch again.
    pub async fn next(&mut self) -> Result<ProcessEventBatch> {
        match self {
            Self::Local(events) => told(events.next().await),
            Self::Remote(events) => events.next().await,
        }
    }
}

fn told(batch: Option<ProcessEventBatch>) -> Result<ProcessEventBatch> {
    batch.ok_or_else(|| anyhow!("the agent stopped"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send<T: Send>(_: T) {}

    #[test]
    fn every_call_can_be_awaited_on_any_executor() {
        fn calls(agent: &Agent, sampler: &mut Sampler, watch: &mut Watch, events: &mut ProcessEvents) {
            send(agent.ping());
            send(agent.snapshot());
            send(agent.subscribe(MetricSpec::default()));
            send(agent.watch(MetricSpec::default()));
            send(watch.next());
            send(agent.run(Command::Kill { pid: 0 }));
            send(agent.watch_service("svc"));
            send(sampler.next());
            send(agent.watch_process_events());
            send(events.next());
        }
        let _ = calls;
    }

    #[test]
    fn the_agent_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Agent>();
        assert_send_sync::<Sampler>();
        assert_send_sync::<Watch>();
        assert_send_sync::<ProcessEvents>();
    }

    #[test]
    fn process_events_in_process_end_as_an_error_like_over_the_pipe() {
        let batch = ProcessEventBatch {
            history_from: 1,
            ..Default::default()
        };
        assert_eq!(told(Some(batch.clone())).map_err(|e| e.to_string()), Ok(batch));
        assert_eq!(told(None).map_err(|e| e.to_string()), Err("the agent stopped".to_string()));
    }
}
