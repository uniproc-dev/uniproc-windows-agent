use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use parking_lot::Mutex;
use uniproc_agent_kit::{Cadence, Monitor};
use uniproc_windows_core::{Demand, Supervisor, SupervisorConfig};

use crate::api::{
    Command, CommandResult, MetricSpec, ProcessInfo, ProcessStates, ServiceStats, Snapshot, Tagged,
};
use crate::commands::Commands;
use crate::feed::Feed;
use crate::profile;
use crate::sampler::Subscriptions;
use crate::scm::{Inventory, Scm, Watcher, Watching};

pub use crate::feed::Published;
pub use crate::sampler::LocalSampler;
pub use crate::scm::ServiceWatch;
pub use uniproc_windows_core::{ProbeCost, SessionHealth};

/// Passports and states are read this often while a client is attached and nobody subscribes.
pub const ATTACHED_PERIOD: Duration = Duration::from_millis(1000);

/// And this often while nobody is attached.
pub const IDLE_PERIOD: Duration = Duration::from_millis(2000);

#[derive(Debug)]
pub enum StartError {
    /// The calling process does not run elevated; the agent needs its full token.
    NotElevated,
    /// The monitoring itself did not start: ETW sessions, providers or threads.
    Failed(anyhow::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotElevated => f.write_str("the process is not elevated"),
            Self::Failed(error) => write!(f, "monitoring did not start: {error:#}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The agent running in this process: the core, the services and the
/// commands. Whoever holds it - the service, its pipe and HTTP API, or an
/// app - reads the same published snapshots. Monitoring stops when the
/// last holder drops it, or at [`stop`](Self::stop).
pub struct Local {
    feed: Arc<Feed>,
    subscriptions: Arc<Subscriptions>,
    commands: Commands,
    watching: Watching,
    running: Mutex<Option<Running>>,
}

struct Running {
    _monitor: Arc<Monitor>,
    _inventory: Inventory,
    _watcher: Watcher,
}

impl Local {
    /// Starts monitoring inside an app, under session names and a store of
    /// its own, so it runs beside the service without touching it. Fails
    /// with `NotElevated` rather than collect a partial picture.
    pub fn start() -> Result<Self, StartError> {
        if !crate::privileges::is_elevated().map_err(StartError::Failed)? {
            return Err(StartError::NotElevated);
        }
        Self::launch(profile::in_app(), ATTACHED_PERIOD).map_err(StartError::Failed)
    }

    /// Starts monitoring under the service's own session names and store, at the idle rate.
    pub fn start_as_service() -> anyhow::Result<Self> {
        Self::launch(profile::service(), IDLE_PERIOD)
    }

    fn launch(config: SupervisorConfig, idle: Duration) -> anyhow::Result<Self> {
        let feed = Arc::new(Feed::new());
        let demand = Demand::new(idle);
        let subscriptions = Subscriptions::new(demand.clone());
        let monitor = Arc::new(Monitor::start(
            "core",
            Cadence {
                period: demand.period(),
                ..Cadence::default()
            },
            move || {
                let mut supervisor = Supervisor::new(config, demand);
                supervisor.start()?;
                Ok(move || supervisor.tick())
            },
            {
                let feed = feed.clone();
                move |report| feed.report(report)
            },
        )?);
        subscriptions.drive(&monitor);
        let scm = Scm::new();
        let inventory = Inventory::start(scm.clone(), {
            let feed = feed.clone();
            move |services| feed.services(services)
        })?;
        let watcher = Watcher::start(scm.clone(), {
            let feed = feed.clone();
            move |name, status| feed.service_status(name, status)
        })?;
        let watching = watcher.watching();
        Ok(Self {
            feed,
            subscriptions,
            commands: Commands::start(scm, watching.clone())?,
            watching,
            running: Mutex::new(Some(Running {
                _monitor: monitor,
                _inventory: inventory,
                _watcher: watcher,
            })),
        })
    }

    /// Stops monitoring while others still hold the agent; reads after it see the last report.
    pub fn stop(&self) {
        self.running.lock().take();
    }

    /// The latest snapshot with what the core says about itself.
    pub fn latest(&self) -> Arc<Published> {
        self.feed.latest()
    }

    /// The states always cover the process list.
    pub fn snapshot(&self) -> Snapshot {
        self.latest().snapshot.clone()
    }

    /// The same `Arc` for as long as the tag holds.
    pub fn processes(&self) -> Tagged<Arc<[ProcessInfo]>> {
        self.latest().snapshot.processes.clone()
    }

    /// Moves when any state moves; `passport_etag` names the list it covers.
    pub fn states(&self) -> Tagged<ProcessStates> {
        self.latest().snapshot.states.clone()
    }

    /// The same `Arc` for as long as the tag holds.
    pub fn services(&self) -> Tagged<Arc<[ServiceStats]>> {
        self.latest().snapshot.services.clone()
    }

    /// Samples what `spec` asks for until the sampler is dropped. The core
    /// samples the union of every live sampler at the shortest interval.
    pub fn subscribe(&self, spec: MetricSpec) -> LocalSampler {
        LocalSampler::new(self.feed.clone(), &self.subscriptions, spec)
    }

    /// Whether a client is attached: passports and states then refresh at
    /// [`ATTACHED_PERIOD`] even while nobody subscribes.
    pub fn set_attached(&self, attached: bool) {
        self.subscriptions
            .set_idle(if attached { ATTACHED_PERIOD } else { IDLE_PERIOD });
    }

    /// Runs on the agent's own command threads; the future needs no
    /// particular runtime. `ERROR_BUSY` while another command runs for the
    /// same process or service. A service stays followed for a minute after
    /// a command on it, so snapshots show its transition as it happens.
    pub fn run(&self, command: Command) -> impl Future<Output = anyhow::Result<CommandResult>> + Send + 'static {
        let answer = self.commands.run(command);
        async move { answer.await.map_err(|_| anyhow!("the command panicked")) }
    }

    /// The service's status now, then every change: what an app shows while
    /// it starts, stops, pauses or resumes one. Ends when the service is
    /// deleted, cannot be opened, or monitoring stops.
    pub fn watch_service(&self, name: &str) -> ServiceWatch {
        self.watching.watch(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{MachineMetric, ProcessMetric};

    #[test]
    fn the_agent_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Local>();
        assert_send_sync::<LocalSampler>();
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn an_elevated_process_sees_the_machine() {
        let agent = Local::start().expect("elevated");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut listed = agent.processes();
        while listed.value.len() < 10 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
            listed = agent.processes();
        }
        assert!(listed.value.len() >= 10, "{} processes", listed.value.len());
        assert!(listed.value.iter().any(|p| p.pid == std::process::id()));

        let snapshot = agent.snapshot();
        if snapshot.states.value.passport_etag == snapshot.processes.etag {
            assert_eq!(snapshot.states.value.states.len(), snapshot.processes.value.len());
        }

        let sampler = agent.subscribe(MetricSpec {
            interval: Duration::from_millis(500),
            processes: [ProcessMetric::WorkingSet, ProcessMetric::CpuUserTime].into_iter().collect(),
            machine: [MachineMetric::Memory].into_iter().collect(),
        });
        let first = futures::executor::block_on(sampler.sample(0));
        let second = futures::executor::block_on(sampler.sample(first.snapshot));
        assert!(second.snapshot > first.snapshot);
        assert_eq!(second.columns.working_set.as_ref().unwrap().len(), second.pids.len());
        assert!(second.columns.handles.is_none(), "not asked for");
        assert!(second.machine.memory.unwrap().total_physical > 0);

        std::thread::sleep(Duration::from_millis(2500));
        assert!(!agent.services().value.is_empty());
        assert!(agent.processes().value.iter().any(|p| p.is_service));
    }
}
