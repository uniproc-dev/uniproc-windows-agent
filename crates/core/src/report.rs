use std::sync::Arc;
use std::time::Instant;

use crate::state::SystemState;
use crate::state::events::ProcessSignature;
use crate::tag::Tagged;

/// What the state held at one tick. Never changes once built.
#[derive(Clone, Debug)]
pub struct Report {
    pub machine: MachineStats,
    pub processes: Tagged<Arc<[Process]>>,
    /// Exactly the pids in `processes`, in the same order.
    pub metrics: Vec<ProcessMetrics>,
    pub samples: Samples,
    pub dropped_by_sink: u64,
    pub sessions: Vec<SessionHealth>,
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

/// Profile samples folded at the last machine snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Samples {
    pub attributed: u64,
    pub unattributed: u64,
    pub idle: u64,
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

/// The machine as a whole. Disk and network are running totals since the agent started.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MachineStats {
    pub total_physical_kb: u64,
    pub available_physical_kb: u64,
    pub used_physical_kb: u64,
    pub cpu_percent: f32,
    pub cpu_max_mhz: u64,
    pub cpu_current_mhz: u64,
    pub cpu_interrupt_percent: f32,
    pub cpu_dpc_percent: f32,

    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_iops: u64,
    pub disk_write_iops: u64,

    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

/// What a process is. Fixed for its lifetime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    /// Exactly what the OS reports; for matching and grouping.
    pub name: String,
    pub cmdline: Vec<String>,
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
}

/// What a process is doing right now, joined to its [`Process`] by pid.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcessMetrics {
    pub pid: u32,
    pub cpu_percent: f32,
    pub working_set_kb: u64,
    pub private_bytes_kb: u64,
    pub peak_working_set_kb: u64,
    /// Resident pages no one else shares; the only memory figure that sums across processes.
    pub private_working_set_kb: u64,

    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_iops: u64,
    pub disk_write_iops: u64,

    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

impl Report {
    /// The process list is taken from `previous` while its etag holds, not rebuilt.
    pub(crate) fn build(
        state: &SystemState,
        previous: Option<&Report>,
        dropped_by_sink: u64,
        sessions: Vec<SessionHealth>,
    ) -> Self {
        let etag = state.processes_etag();
        let processes = match previous {
            Some(previous) if previous.processes.etag == etag => previous.processes.clone(),
            _ => Tagged {
                etag,
                value: processes(state),
            },
        };
        let (attributed, unattributed, idle) = state.sample_counts();
        Self {
            machine: machine(state),
            processes,
            metrics: metrics(state),
            samples: Samples {
                attributed,
                unattributed,
                idle,
            },
            dropped_by_sink,
            sessions,
            taken_at: Instant::now(),
        }
    }
}

fn signature(s: ProcessSignature) -> SignatureStatus {
    match s {
        ProcessSignature::Unknown => SignatureStatus::Unknown,
        ProcessSignature::Unsigned => SignatureStatus::Unsigned,
        ProcessSignature::Microsoft => SignatureStatus::Microsoft,
        ProcessSignature::ThirdParty => SignatureStatus::ThirdParty,
    }
}

fn processes(state: &SystemState) -> Arc<[Process]> {
    state
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
        })
        .collect()
}

fn metrics(state: &SystemState) -> Vec<ProcessMetrics> {
    state
        .entries()
        .map(|e| {
            let mem = e.memory.as_ref();
            ProcessMetrics {
                pid: e.pid,
                cpu_percent: e.cpu.total_percent as f32,
                working_set_kb: mem.map_or(0, |m| m.working_set_bytes / 1024),
                private_bytes_kb: mem.map_or(0, |m| m.private_bytes / 1024),
                peak_working_set_kb: mem.map_or(0, |m| m.peak_working_set_bytes / 1024),
                private_working_set_kb: mem.map_or(0, |m| m.private_working_set_bytes / 1024),
                disk_read_bytes: e.disk.read_bytes,
                disk_write_bytes: e.disk.write_bytes,
                disk_read_iops: e.disk.read_ops,
                disk_write_iops: e.disk.write_ops,
                net_rx_bytes: e.network.recv_bytes,
                net_tx_bytes: e.network.sent_bytes,
            }
        })
        .collect()
}

fn machine(state: &SystemState) -> MachineStats {
    let totals = state.machine_totals();
    let mut out = MachineStats {
        disk_read_bytes: totals.disk_read_bytes,
        disk_write_bytes: totals.disk_write_bytes,
        disk_read_iops: totals.disk_read_ops,
        disk_write_iops: totals.disk_write_ops,
        net_rx_bytes: totals.net_rx_bytes,
        net_tx_bytes: totals.net_tx_bytes,
        ..Default::default()
    };
    if let Some(m) = state.machine() {
        out.total_physical_kb = m.total_physical_kb;
        out.available_physical_kb = m.available_physical_kb;
        out.used_physical_kb = m.used_physical_kb;
        out.cpu_percent = m.cpu_percent;
        out.cpu_max_mhz = m.cpu_max_mhz;
        out.cpu_current_mhz = m.cpu_current_mhz;
        out.cpu_interrupt_percent = m.cpu_interrupt_percent;
        out.cpu_dpc_percent = m.cpu_dpc_percent;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::events::{MemorySnapshot, ProcessStarted, StateChange};

    fn state() -> SystemState {
        let mut s = SystemState::new();
        s.apply(StateChange::ProcessStarted(Box::new(ProcessStarted {
            pid: 100,
            parent_pid: 4,
            session_id: 1,
            image_name: "a.exe".to_string(),
            command_line: vec!["a.exe".to_string(), "-x".to_string()],
            package_full_name: String::new(),
            package_relative_app_id: String::new(),
            is_kernel_process: false,
        })));
        s.apply(StateChange::Memory(vec![MemorySnapshot {
            pid: 100,
            working_set_bytes: 8192,
            private_working_set_bytes: 4096,
            ..Default::default()
        }]));
        s
    }

    #[test]
    fn a_process_is_listed_with_what_it_is() {
        let listed = processes(&state());
        assert_eq!(listed.len(), 1);
        let p = &listed[0];
        assert_eq!((p.pid, p.parent_pid, p.session_id), (100, 4, 1));
        assert_eq!(p.name, "a.exe");
        assert_eq!(p.cmdline, ["a.exe", "-x"]);
    }

    #[test]
    fn metrics_are_in_kilobytes_and_cover_the_list() {
        let s = state();
        let report = Report::build(&s, None, 0, Vec::new());
        assert_eq!(report.processes.etag, s.processes_etag());
        assert_eq!(report.metrics.len(), report.processes.value.len());
        assert_eq!(report.metrics[0].working_set_kb, 8);
        assert_eq!(report.metrics[0].private_working_set_kb, 4);
    }

    #[test]
    fn an_unchanged_list_is_taken_from_the_previous_report() {
        let s = state();
        let first = Report::build(&s, None, 0, Vec::new());
        let again = Report::build(&s, Some(&first), 0, Vec::new());
        assert!(Arc::ptr_eq(&first.processes.value, &again.processes.value));
    }

    #[test]
    fn a_moved_tag_builds_the_list_again() {
        let mut s = state();
        let first = Report::build(&s, None, 0, Vec::new());
        s.apply(StateChange::ProcessStarted(Box::new(ProcessStarted {
            pid: 200,
            image_name: "b.exe".to_string(),
            ..Default::default()
        })));
        let next = Report::build(&s, Some(&first), 0, Vec::new());
        assert_ne!(next.processes.etag, first.processes.etag);
        assert_eq!(next.processes.value.len(), 2);
    }

    #[test]
    fn a_machine_not_sampled_yet_is_all_zero() {
        assert_eq!(machine(&SystemState::new()), MachineStats::default());
    }
}
