#[derive(Clone, Debug, Default)]
pub struct ProcessStarted {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub image_name: String,
    pub command_line: Vec<String>,
    pub package_full_name: String,
    pub package_relative_app_id: String,
    /// Kernel pseudo-process (Idle, System, Registry, ...): no image on disk.
    pub is_kernel_process: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProcessSignature {
    /// Not checked yet, or the check itself failed.
    #[default]
    Unknown,
    Unsigned,
    Microsoft,
    ThirdParty,
}

/// Follow-up enrichment for an already reported process: everything that
/// requires opening the process / inspecting its image file.
#[derive(Clone, Debug, Default)]
pub struct ProcessEnriched {
    pub pid: u32,
    pub command_line: Vec<String>,
    pub image_path: String,
    pub signature: ProcessSignature,
    pub is_kernel_process: bool,
    pub is_windows_process: bool,
}

#[derive(Clone, Debug, Default)]
pub struct MemorySnapshot {
    pub pid: u32,
    pub virtual_size_bytes: u64,
    pub peak_virtual_size_bytes: u64,
    pub working_set_bytes: u64,
    pub peak_working_set_bytes: u64,
    pub private_working_set_bytes: u64,
    pub private_bytes: u64,
    pub peak_private_bytes: u64,
    pub paged_pool_bytes: u64,
    pub peak_paged_pool_bytes: u64,
    pub nonpaged_pool_bytes: u64,
    pub peak_nonpaged_pool_bytes: u64,
    pub page_fault_count: u32,
    pub shared_commit_bytes: u64,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MachineSnapshot {
    pub total_physical_kb: u64,
    pub available_physical_kb: u64,
    pub used_physical_kb: u64,
    pub cpu_percent: f32,
    pub cpu_max_mhz: u64,
    pub cpu_current_mhz: u64,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug)]
pub struct DiskEvent {
    pub pid: u32,
    pub event_type: DiskEventType,
    pub transfer_size: u64,
    pub byte_offset: i64,
    pub disk_number: u32,
    pub elapsed_time: u64,
}

#[derive(Clone, Debug)]
pub enum DiskEventType {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Debug)]
pub struct NetworkEvent {
    pub pid: u32,
    pub event_type: NetworkEventType,
    pub proto: NetworkProto,
    pub size: u32,
    pub src_addr: std::net::IpAddr,
    pub src_port: u16,
    pub dst_addr: std::net::IpAddr,
    pub dst_port: u16,
}

#[derive(Clone, Debug)]
pub enum NetworkEventType {
    Send,
    Recv,
    Connect,
    Disconnect,
    Accept,
}

#[derive(Clone, Debug)]
pub enum NetworkProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub enum StateChange {
    ProcessStarted(ProcessStarted),
    ProcessRundown(ProcessStarted),
    /// Enrichment resolved off the shared ETW pump thread, after the initial
    /// `ProcessStarted`/`ProcessRundown` already inserted the entry.
    ProcessEnriched(ProcessEnriched),
    ProcessStopped(u32),
    ThreadStarted { pid: u32, tid: u32 },
    ThreadStopped { tid: u32 },
    /// Whole-set snapshots from the periodic inventory; they replace the
    /// previous sets instead of diffing per process.
    ServicePidsSnapshot(Vec<u32>),
    VisibleWindowPidsSnapshot(Vec<u32>),
    Memory(MemorySnapshot),
    Machine(MachineSnapshot),
    Disk(DiskEvent),
    Network(NetworkEvent),
    CpuUsage { pid: u32, percent: f64 },
}
