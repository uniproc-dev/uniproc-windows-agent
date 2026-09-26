mod snapshot;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::api::{
    Command, CommandResult, MachineStats, ProcessInfo, ProcessMetricsSnapshot, ProcessPriority,
    ServiceStats, Snapshot, Tagged,
};
use crate::commands::Commands;
use crate::commands::process;
use crate::commands::services::ServiceAction;
use crate::monitor::Monitor;
use crate::providers::{EMBEDDED, supervisor};
use crate::settings::ATTACHED_MEMORY_INTERVAL_MS;

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

/// The agent running inside the caller's process. Its ETW sessions and
/// signature store are its own, so it runs beside the service without
/// touching it. Monitoring stops when this is dropped.
pub struct Embedded {
    monitor: Monitor,
    commands: Commands,
    processes: Mutex<Option<Tagged<Arc<[ProcessInfo]>>>>,
    services: Mutex<Option<Tagged<Arc<[ServiceStats]>>>>,
}

impl Embedded {
    /// Starts monitoring; fails with `NotElevated` rather than collect a partial picture.
    pub fn start() -> Result<Self, StartError> {
        if !crate::privileges::is_elevated().map_err(StartError::Failed)? {
            return Err(StartError::NotElevated);
        }
        let monitor = Monitor::start(supervisor(&EMBEDDED)).map_err(StartError::Failed)?;
        monitor
            .settings()
            .set_memory_interval(Duration::from_millis(ATTACHED_MEMORY_INTERVAL_MS));
        Ok(Self::from_monitor(monitor))
    }

    pub(crate) fn from_monitor(monitor: Monitor) -> Self {
        Self {
            monitor,
            commands: Commands::new(),
            processes: Mutex::new(None),
            services: Mutex::new(None),
        }
    }

    #[cfg(feature = "service")]
    pub(crate) fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    /// Everything under one lock, so the metrics always join the process list.
    pub fn snapshot(&self) -> Snapshot {
        self.monitor.read(|state| Snapshot {
            machine: snapshot::machine(state),
            services: cached(&self.services, state.services_etag(), || snapshot::services(state)),
            processes: cached(&self.processes, state.processes_etag(), || {
                snapshot::processes(state)
            }),
            metrics: snapshot::process_metrics(state).metrics,
        })
    }

    pub fn machine(&self) -> MachineStats {
        self.monitor.read(snapshot::machine)
    }

    /// The same `Arc` for as long as the tag holds.
    pub fn processes(&self) -> Tagged<Arc<[ProcessInfo]>> {
        self.monitor.read(|state| {
            cached(&self.processes, state.processes_etag(), || snapshot::processes(state))
        })
    }

    /// Always fresh; a `processes_etag` other than the one held means the list must be read again before joining by pid.
    pub fn process_metrics(&self) -> ProcessMetricsSnapshot {
        self.monitor.read(snapshot::process_metrics)
    }

    /// The same `Arc` for as long as the tag holds.
    pub fn services(&self) -> Tagged<Arc<[ServiceStats]>> {
        self.monitor.read(|state| {
            cached(&self.services, state.services_etag(), || snapshot::services(state))
        })
    }

    pub fn set_memory_interval(&self, interval: Duration) {
        self.monitor.settings().set_memory_interval(interval);
    }

    pub fn set_cpu_interval(&self, interval: Duration) {
        self.monitor.settings().set_cpu_interval(interval);
    }

    /// Blocks for as long as the command takes; a service restart up to half a minute.
    pub fn run(&self, command: Command) -> CommandResult {
        match command {
            Command::Kill { pid } => self.kill(pid),
            Command::Suspend { pid } => self.suspend(pid),
            Command::Resume { pid } => self.resume(pid),
            Command::SetPriority { pid, priority } => self.set_priority(pid, priority),
            Command::SetAffinity { pid, mask } => self.set_affinity(pid, mask),
            Command::ServiceStart { name } => self.service_start(&name),
            Command::ServiceStop { name } => self.service_stop(&name),
            Command::ServicePause { name } => self.service_pause(&name),
            Command::ServiceResume { name } => self.service_resume(&name),
            Command::ServiceRestart { name } => self.service_restart(&name),
        }
    }

    pub fn kill(&self, pid: u32) -> CommandResult {
        process::kill(pid)
    }

    pub fn suspend(&self, pid: u32) -> CommandResult {
        process::suspend(pid)
    }

    pub fn resume(&self, pid: u32) -> CommandResult {
        process::resume(pid)
    }

    pub fn set_priority(&self, pid: u32, priority: ProcessPriority) -> CommandResult {
        process::set_priority(pid, priority)
    }

    pub fn set_affinity(&self, pid: u32, mask: u64) -> CommandResult {
        process::set_affinity(pid, mask)
    }

    /// Blocks until the SCM has taken the control.
    pub fn service_start(&self, name: &str) -> CommandResult {
        self.commands.control_service(name, ServiceAction::Start)
    }

    /// Blocks until the SCM has taken the control.
    pub fn service_stop(&self, name: &str) -> CommandResult {
        self.commands.control_service(name, ServiceAction::Stop)
    }

    /// Blocks until the SCM has taken the control.
    pub fn service_pause(&self, name: &str) -> CommandResult {
        self.commands.control_service(name, ServiceAction::Pause)
    }

    /// Blocks until the SCM has taken the control.
    pub fn service_resume(&self, name: &str) -> CommandResult {
        self.commands.control_service(name, ServiceAction::Resume)
    }

    /// Blocks until the service has stopped and been started again, up to half a minute.
    pub fn service_restart(&self, name: &str) -> CommandResult {
        self.commands.restart_service(name)
    }
}

fn cached<T: ?Sized>(
    slot: &Mutex<Option<Tagged<Arc<T>>>>,
    etag: u64,
    build: impl FnOnce() -> Arc<T>,
) -> Tagged<Arc<T>> {
    let mut slot = slot.lock();
    if let Some(hit) = slot.as_ref().filter(|held| held.etag == etag) {
        return hit.clone();
    }
    let fresh = Tagged {
        etag,
        value: build(),
    };
    *slot = Some(fresh.clone());
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Embedded>();
    }

    #[test]
    fn an_unchanged_tag_hands_back_the_same_list() {
        let slot: Mutex<Option<Tagged<Arc<[u32]>>>> = Mutex::new(None);
        let first = cached(&slot, 7, || Arc::from([1u32, 2]));
        let again = cached(&slot, 7, || unreachable!("the tag has not moved"));
        assert!(Arc::ptr_eq(&first.value, &again.value));
    }

    #[test]
    fn a_new_tag_builds_the_list_again() {
        let slot: Mutex<Option<Tagged<Arc<[u32]>>>> = Mutex::new(None);
        let first = cached(&slot, 7, || Arc::from([1u32]));
        let next = cached(&slot, 8, || Arc::from([1u32, 2]));
        assert!(!Arc::ptr_eq(&first.value, &next.value));
        assert_eq!((next.etag, next.value.len()), (8, 2));
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn an_elevated_process_sees_the_machine() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let agent = Embedded::start().expect("elevated");

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
    }
}
