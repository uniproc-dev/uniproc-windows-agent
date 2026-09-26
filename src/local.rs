use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use uniproc_windows_core::{CollectorSettings, SupervisorConfig};

use crate::api::{
    Command, CommandResult, MachineStats, ProcessInfo, ProcessMetricsSnapshot, ServiceStats,
    Snapshot, Tagged,
};
use crate::commands::Commands;
use crate::feed::Feed;

pub use crate::feed::Published;
pub use uniproc_windows_core::{Samples, SessionHealth};

/// Memory is read this often while someone watches.
pub const ATTACHED_MEMORY_INTERVAL: Duration = Duration::from_millis(1000);

/// And this often while nobody does.
pub const IDLE_MEMORY_INTERVAL: Duration = Duration::from_millis(2000);
use crate::monitor::Monitor;
use crate::profile;
use crate::scm::{Inventory, Scm};

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

/// The agent running in this process: the core, the service inventory and
/// the commands. Whoever holds it - the service, its pipe and HTTP API, or
/// an app - reads the same published snapshots. Monitoring stops when the
/// last holder drops it, or at [`stop`](Self::stop).
pub struct Local {
    feed: Arc<Feed>,
    settings: CollectorSettings,
    commands: Commands,
    running: Mutex<Option<(Monitor, Inventory)>>,
}

impl Local {
    /// Starts monitoring inside an app, under session names and a store of
    /// its own, so it runs beside the service without touching it. Fails
    /// with `NotElevated` rather than collect a partial picture.
    pub fn start() -> Result<Self, StartError> {
        if !crate::privileges::is_elevated().map_err(StartError::Failed)? {
            return Err(StartError::NotElevated);
        }
        let agent = Self::launch(profile::in_app()).map_err(StartError::Failed)?;
        agent.set_memory_interval(ATTACHED_MEMORY_INTERVAL);
        Ok(agent)
    }

    /// Starts monitoring under the service's own session names and store, at the idle rate.
    pub fn start_as_service() -> anyhow::Result<Self> {
        let agent = Self::launch(profile::service())?;
        agent.set_memory_interval(IDLE_MEMORY_INTERVAL);
        Ok(agent)
    }

    fn launch(config: SupervisorConfig) -> anyhow::Result<Self> {
        let feed = Arc::new(Feed::new());
        let settings = CollectorSettings::default();
        let monitor = Monitor::start(config, settings.clone(), {
            let feed = feed.clone();
            move |report| feed.report(report)
        })?;
        let scm = Scm::new();
        let inventory = Inventory::start(scm.clone(), {
            let feed = feed.clone();
            move |services| feed.services(services)
        })?;
        Ok(Self {
            feed,
            settings,
            commands: Commands::new(scm),
            running: Mutex::new(Some((monitor, inventory))),
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

    /// The metrics always join the process list.
    pub fn snapshot(&self) -> Snapshot {
        self.latest().snapshot.clone()
    }

    pub fn machine(&self) -> MachineStats {
        self.latest().snapshot.machine.clone()
    }

    /// The same `Arc` for as long as the tag holds.
    pub fn processes(&self) -> Tagged<Arc<[ProcessInfo]>> {
        self.latest().snapshot.processes.clone()
    }

    /// A `processes_etag` other than the one held means the list must be read again before joining by pid.
    pub fn process_metrics(&self) -> ProcessMetricsSnapshot {
        let latest = self.latest();
        ProcessMetricsSnapshot {
            processes_etag: latest.snapshot.processes.etag,
            metrics: latest.snapshot.metrics.clone(),
        }
    }

    /// The same `Arc` for as long as the tag holds.
    pub fn services(&self) -> Tagged<Arc<[ServiceStats]>> {
        self.latest().snapshot.services.clone()
    }

    pub fn set_memory_interval(&self, interval: Duration) {
        self.settings.set_memory_interval(interval);
    }

    pub fn set_cpu_interval(&self, interval: Duration) {
        self.settings.set_cpu_interval(interval);
    }

    /// Blocks for as long as the command takes; a service restart up to half a minute.
    pub fn run(&self, command: Command) -> CommandResult {
        self.commands.run(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Local>();
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

        let metrics = agent.process_metrics();
        if metrics.processes_etag == listed.etag {
            assert_eq!(metrics.metrics.len(), listed.value.len());
        }

        std::thread::sleep(Duration::from_millis(2500));
        let machine = agent.machine();
        assert!(machine.total_physical_kb > 0);
        assert!(!agent.services().value.is_empty());
        assert!(agent.processes().value.iter().any(|p| p.is_service));
    }
}
