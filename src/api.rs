use std::sync::Arc;

pub use uniproc_windows_core::{
    Architecture, Columns, DpiAwareness, ExtendedCfg, IoPriority, Isolation, MachineCpu,
    MachineDisk, MachineMemory, MachineMetric, MachineMetrics, MachineNetwork, MachineSample,
    MetricSpec, Mitigations, NO_DATA_U32, NO_DATA_U64, ProcessMetric, ProcessMetrics, ProcessPriority, ProcessState,
    Sample, SignatureStatus, SmolStr, StackProtection, Tagged, UacVirtualization,
};

/// Name the agent's Windows service is registered under.
pub const SERVICE_NAME: &str = "UniprocProcessMonitor";

/// Name the service shows in the Services console.
pub const SERVICE_DISPLAY_NAME: &str = "Uniproc Process Monitor";

/// Ok, or the Win32 error code; an NTSTATUS for suspend and resume.
pub type CommandResult = Result<(), u32>;

/// How every process runs, for exactly the processes listed under `passport_etag`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessStates {
    pub passport_etag: u64,
    pub states: Arc<[ProcessState]>,
}

/// The conditional lists at one moment: `states` covers exactly `processes`.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub services: Tagged<Arc<[ServiceStats]>>,
    pub processes: Tagged<Arc<[ProcessInfo]>>,
    pub states: Tagged<ProcessStates>,
}

/// One push of a watch: the lists as they stand, the sample taken against
/// them, and what moved in the lists since the update before.
#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    pub snapshot: Snapshot,
    /// Its rows are the processes `snapshot.processes` lists.
    pub sample: Sample,
    pub changes: Changes,
}

/// What moved in the lists since the update before, keyed by pid and
/// sequence number, the join key of the sample.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    /// No update came before, or the lists were fetched again: everything is new.
    pub full: bool,
    /// Processes that started, or whose passport changed.
    pub passports: Vec<(u32, u64)>,
    /// Processes that exited; their states went with them.
    pub left: Vec<(u32, u64)>,
    /// Processes whose state changed, including every one that started.
    pub states: Vec<(u32, u64)>,
    pub services: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Kill { pid: u32 },
    Suspend { pid: u32 },
    Resume { pid: u32 },
    SetPriority { pid: u32, priority: ProcessPriority },
    SetAffinity { pid: u32, mask: u64 },
    ServiceStart { name: String },
    ServiceStop { name: String },
    ServicePause { name: String },
    ServiceResume { name: String },
    /// Waits for the service to stop, up to half a minute, then starts it.
    ServiceRestart { name: String },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ServiceState {
    #[default]
    Unknown,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

/// One service right now, as the SCM reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceStatus {
    pub state: ServiceState,
    /// 0 while the service has no process.
    pub pid: u32,
    /// Win32 code the service stopped with; 0 for none.
    pub exit_code: u32,
    /// The service's own code, when `exit_code` is ERROR_SERVICE_SPECIFIC_ERROR.
    pub service_exit_code: u32,
    /// Grows while a pending start, stop, pause or continue makes progress.
    pub checkpoint: u32,
    /// How long the service expects its pending step to take, in milliseconds.
    pub wait_hint_ms: u32,
}

impl ServiceState {
    pub fn is_pending(self) -> bool {
        matches!(
            self,
            Self::StartPending | Self::StopPending | Self::ContinuePending | Self::PausePending
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceStats {
    pub name: String,
    pub display_name: String,
    pub pid: u32,
    pub state: ServiceState,
    pub load_group: String,
    pub description: String,
    /// Path the SCM starts the service from, as its config gives it.
    pub image_path: String,
}

/// What a process is. Fixed for its lifetime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    /// Exactly what the OS reports; for matching and grouping.
    pub name: SmolStr,
    /// Shared with the core's passport; cloning it copies no argument.
    pub cmdline: Arc<[String]>,
    pub package_full_name: SmolStr,
    pub package_relative_app_id: SmolStr,

    pub is_service: bool,
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
    /// The join key for states and samples: never reused within a boot, 0
    /// only for the Idle process.
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
