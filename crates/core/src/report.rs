use std::sync::Arc;
use std::time::Instant;

use smol_str::SmolStr;

use crate::model::{
    Architecture, DpiAwareness, Isolation, Mitigations, ProcessState, UacVirtualization,
};
use crate::sample::Sample;
use crate::state::events::ProcessSignature;
use crate::state::process::ProcessEntry;

/// What changed in the core's picture of the machine since the last tick.
/// The set of processes changes only with a sample.
#[derive(Clone, Debug, Default)]
pub struct Diff {
    /// Processes that left, as pid and sequence number.
    pub gone: Vec<(u32, u64)>,
    /// Passports of the processes that joined, and of those that changed.
    pub passports: Vec<Process>,
    /// States of the processes that joined, and of those that changed.
    pub states: Vec<ProcessState>,
    /// The sample this tick took; its rows are exactly the processes once
    /// this diff is applied.
    pub sample: Option<Arc<Sample>>,
}

/// What the core says about itself at one tick.
#[derive(Clone, Debug)]
pub struct Health {
    pub dropped_by_sink: u64,
    pub sessions: Vec<SessionHealth>,
    /// Why the last attempt to read the process list failed; None once it reads.
    pub snapshot_error: Option<String>,
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
    pub name: SmolStr,
    /// Shared with the core's own entry; cloning it copies no argument.
    pub cmdline: Arc<[String]>,
    pub package_full_name: SmolStr,
    pub package_relative_app_id: SmolStr,

    pub is_kernel_process: bool,
    pub is_windows_process: bool,
    pub signature: SignatureStatus,
    pub image_path: SmolStr,

    /// For display only; empty when nothing resolved, then show `name`.
    pub display_name: SmolStr,

    /// Pid of the conhost serving the process's console, or 0.
    pub console_host_pid: u32,

    /// FILETIME; 0 when unknown.
    pub start_time: u64,
    /// Never reused within a boot; 0 only for the Idle process.
    pub sequence_number: u64,
    /// `DOMAIN\name` of the token's user.
    pub user: SmolStr,
    pub architecture: Architecture,
    pub elevated: Option<bool>,
    pub uac_virtualization: UacVirtualization,
    pub isolation: Isolation,
    pub dpi_awareness: DpiAwareness,
    /// `None` when the process could not be queried.
    pub mitigations: Option<Mitigations>,
    /// A package's PublisherDisplayName, otherwise the signer's subject name.
    pub publisher: SmolStr,
}

fn signature(s: ProcessSignature) -> SignatureStatus {
    match s {
        ProcessSignature::Unknown => SignatureStatus::Unknown,
        ProcessSignature::Unsigned => SignatureStatus::Unsigned,
        ProcessSignature::Microsoft => SignatureStatus::Microsoft,
        ProcessSignature::ThirdParty => SignatureStatus::ThirdParty,
    }
}

pub(crate) fn passport(e: &ProcessEntry) -> Process {
    Process {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_passport_is_what_the_entry_says_and_shares_its_command_line() {
        let entry = ProcessEntry {
            pid: 100,
            parent_pid: 4,
            sequence_number: 1100,
            start_time: 42,
            image_name: "p100.exe".into(),
            command_line: Arc::from(["p100.exe".to_string(), "-x".to_string()]),
            signature: ProcessSignature::Microsoft,
            ..Default::default()
        };
        let p = passport(&entry);
        assert_eq!((p.pid, p.parent_pid, p.sequence_number, p.start_time), (100, 4, 1100, 42));
        assert_eq!(p.name, "p100.exe");
        assert_eq!(p.signature, SignatureStatus::Microsoft);
        assert!(Arc::ptr_eq(&p.cmdline, &entry.command_line));
    }
}
