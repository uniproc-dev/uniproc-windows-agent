use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::model::{
    Architecture, DpiAwareness, Isolation, Mitigations, ProcessState, UacVirtualization,
};
use crate::sample::Sample;
use crate::state::SystemState;
use crate::state::events::ProcessSignature;
use uniproc_agent_kit::Tagged;

/// What the state held at one tick. Never changes once built.
#[derive(Clone, Debug)]
pub struct Report {
    /// Sorted by pid.
    pub processes: Tagged<Arc<[Process]>>,
    /// One per process, in the same order, as of the last sample.
    pub states: Arc<[ProcessState]>,
    /// The last sample; its rows are exactly `processes`.
    pub sample: Arc<Sample>,
    pub dropped_by_sink: u64,
    pub sessions: Vec<SessionHealth>,
    /// What each probe costs the tick.
    pub costs: Vec<ProbeCost>,
    pub taken_at: Instant,
}

/// One of the core's ETW sessions. Losses count from the session's start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionHealth {
    pub name: String,
    /// ETW still has the session; false once someone stopped it from outside.
    pub running: bool,
    /// Its events are still being read.
    pub pumping: bool,
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
    pub log_buffers_lost: u32,
    pub buffers_written: u32,
    pub buffers: u32,
    pub free_buffers: u32,
}

impl SessionHealth {
    pub fn is_healthy(&self) -> bool {
        self.running && self.pumping
    }
}

/// How long one probe takes, over every tick that ran it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeCost {
    pub name: &'static str,
    pub runs: u64,
    pub last: Duration,
    pub mean: Duration,
    pub max: Duration,
}

impl ProbeCost {
    pub fn record(&mut self, took: Duration) {
        self.runs += 1;
        self.last = took;
        self.max = self.max.max(took);
        let total = self.mean.as_nanos() * (self.runs as u128 - 1) + took.as_nanos();
        self.mean = Duration::from_nanos((total / self.runs as u128) as u64);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SignatureStatus {
    /// Not checked yet, or the check itself failed.
    #[default]
    Unknown,
    Unsigned,
    Microsoft,
    ThirdParty,
}

/// What a process is. Fixed for its lifetime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    /// Exactly what the OS reports; for matching and grouping.
    pub name: String,
    /// Shared with the core's own entry; cloning it copies no argument.
    pub cmdline: Arc<[String]>,
    pub package_full_name: String,
    pub package_relative_app_id: String,

    pub is_kernel_process: bool,
    pub is_windows_process: bool,
    pub signature: SignatureStatus,
    pub image_path: String,

    /// For display only; empty when nothing resolved, then show `name`.
    pub display_name: String,

    /// Pid of the conhost serving the process's console, or 0.
    pub console_host_pid: u32,

    /// FILETIME; 0 when unknown.
    pub start_time: u64,
    /// Never reused within a boot; 0 only for the Idle process.
    pub sequence_number: u64,
    /// `DOMAIN\name` of the token's user.
    pub user: String,
    pub architecture: Architecture,
    pub elevated: Option<bool>,
    pub uac_virtualization: UacVirtualization,
    pub isolation: Isolation,
    pub dpi_awareness: DpiAwareness,
    /// `None` when the process could not be queried.
    pub mitigations: Option<Mitigations>,
    /// A package's PublisherDisplayName, otherwise the signer's subject name.
    pub publisher: String,
}

fn signature(s: ProcessSignature) -> SignatureStatus {
    match s {
        ProcessSignature::Unknown => SignatureStatus::Unknown,
        ProcessSignature::Unsigned => SignatureStatus::Unsigned,
        ProcessSignature::Microsoft => SignatureStatus::Microsoft,
        ProcessSignature::ThirdParty => SignatureStatus::ThirdParty,
    }
}

/// The passports, taken from `previous` while the etag holds, sorted by pid.
pub(crate) fn processes(state: &SystemState, previous: Option<&Tagged<Arc<[Process]>>>) -> Tagged<Arc<[Process]>> {
    let etag = state.processes_etag();
    if let Some(previous) = previous.filter(|p| p.etag == etag) {
        return previous.clone();
    }
    let mut value: Vec<Process> = state
        .entries()
        .map(|e| Process {
            pid: e.pid,
            parent_pid: e.parent_pid,
            session_id: e.session_id,
            name: e.image_name.clone(),
            cmdline: e.command_line.clone(),
            package_full_name: e.package_name.clone(),
            package_relative_app_id: e.package_relative_app_id.clone(),
            is_kernel_process: e.is_kernel_process,
            is_windows_process: e.is_windows_process,
            signature: signature(e.signature),
            image_path: e.image_path.clone(),
            display_name: e.display_name.clone(),
            console_host_pid: e.console_host_pid,
            start_time: e.start_time,
            sequence_number: e.sequence_number,
            user: e.user.clone(),
            architecture: e.architecture,
            elevated: e.elevated,
            uac_virtualization: e.uac_virtualization,
            isolation: e.isolation,
            dpi_awareness: e.dpi_awareness,
            mitigations: e.mitigations,
            publisher: e.publisher.clone(),
        })
        .collect();
    value.sort_unstable_by_key(|p| p.pid);
    Tagged {
        etag,
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Row;
    use crate::state::events::{ProcessEnriched, StateChange};
    use crate::state::process::Sighted;

    fn state(pids: &[u32]) -> SystemState {
        let mut s = SystemState::new();
        let rows: Vec<Row> = pids
            .iter()
            .map(|&pid| Row {
                pid,
                parent_pid: 4,
                sequence_number: pid as u64 + 1000,
                create_time: 42,
                ..Default::default()
            })
            .collect();
        s.reconcile(&rows, |row| Sighted {
            image_name: format!("p{}.exe", row.pid),
            ..Default::default()
        });
        s
    }

    #[test]
    fn a_process_is_listed_with_what_it_is() {
        let mut s = state(&[100]);
        s.apply(StateChange::ProcessEnriched(Box::new(ProcessEnriched {
            pid: 100,
            sequence_number: 1100,
            command_line: vec!["a.exe".into(), "-x".into()],
            ..Default::default()
        })));
        let listed = processes(&s, None);
        let p = &listed.value[0];
        assert_eq!((p.pid, p.parent_pid, p.sequence_number, p.start_time), (100, 4, 1100, 42));
        assert_eq!(p.name, "p100.exe");
        assert_eq!(*p.cmdline, ["a.exe", "-x"]);
    }

    #[test]
    fn the_list_is_sorted_by_pid() {
        let listed = processes(&state(&[300, 100, 200]), None);
        let pids: Vec<u32> = listed.value.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [100, 200, 300]);
    }

    #[test]
    fn an_unchanged_list_is_taken_from_the_previous_report() {
        let s = state(&[100]);
        let first = processes(&s, None);
        let again = processes(&s, Some(&first));
        assert!(Arc::ptr_eq(&first.value, &again.value));
    }

    #[test]
    fn a_probe_cost_keeps_its_mean_and_worst() {
        let mut cost = ProbeCost::default();
        for ms in [10, 20, 30] {
            cost.record(Duration::from_millis(ms));
        }
        assert_eq!((cost.runs, cost.last, cost.max), (3, Duration::from_millis(30), Duration::from_millis(30)));
        assert_eq!(cost.mean, Duration::from_millis(20));
    }
}
