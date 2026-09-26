use std::sync::Arc;

pub use uniproc_windows_core::{MachineStats, ProcessMetrics, SignatureStatus, Tagged};

/// Name the agent's Windows service is registered under.
pub const SERVICE_NAME: &str = "UniprocProcessMonitor";

/// Name the service shows in the Services console.
pub const SERVICE_DISPLAY_NAME: &str = "Uniproc Process Monitor";

/// Ok, or the Win32 error code; an NTSTATUS for suspend and resume.
pub type CommandResult = Result<(), u32>;

/// Metrics for exactly the processes listed under `processes_etag`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcessMetricsSnapshot {
    pub processes_etag: u64,
    pub metrics: Vec<ProcessMetrics>,
}

/// Everything at one moment: `metrics` covers exactly the pids in `processes`.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub machine: MachineStats,
    pub services: Tagged<Arc<[ServiceStats]>>,
    pub processes: Tagged<Arc<[ProcessInfo]>>,
    pub metrics: Vec<ProcessMetrics>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcessPriority {
    Idle,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    Realtime,
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
    pub name: String,
    pub cmdline: Vec<String>,
    pub package_full_name: String,
    pub package_relative_app_id: String,

    pub is_service: bool,
    pub is_kernel_process: bool,
    pub is_windows_process: bool,
    pub signature: SignatureStatus,
    pub image_path: String,

    /// For display only; empty when nothing resolved, then show `name`.
    pub display_name: String,

    /// Pid of the conhost serving the process's console, or 0.
    pub console_host_pid: u32,
}
