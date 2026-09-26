/// Name the agent's Windows service is registered under.
pub const SERVICE_NAME: &str = "UniprocProcessMonitor";

/// Name the service shows in the Services console.
pub const SERVICE_DISPLAY_NAME: &str = "Uniproc Process Monitor";

/// Ok, or the Win32 error code; an NTSTATUS for suspend and resume.
pub type CommandResult = Result<(), u32>;

/// A value and the tag it was taken under: an unchanged tag means an unchanged value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tagged<T> {
    pub etag: u64,
    pub value: T,
}

/// Metrics for exactly the processes listed under `processes_etag`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcessMetricsSnapshot {
    pub processes_etag: u64,
    pub metrics: Vec<ProcessMetrics>,
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

/// What a process is doing right now, joined to [`ProcessInfo`] by pid.
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
