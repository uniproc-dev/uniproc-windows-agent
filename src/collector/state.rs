use std::collections::HashMap;


#[derive(Clone, Debug, Default)]
pub struct ProcessStarted {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub image_name: String,
    pub command_line: String,
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
    ProcessStopped(u32),
    ThreadStarted { pid: u32, tid: u32 },
    ThreadStopped { tid: u32 },
    Memory(MemorySnapshot),
    Disk(DiskEvent),
    Network(NetworkEvent),
    CpuUsage { pid: u32, percent: f64 },
}

#[derive(Default, Debug, Clone)]
pub struct CpuStats {
    pub total_percent: f64,
}

#[derive(Default, Debug, Clone)]
pub struct DiskStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}

#[derive(Default, Debug, Clone)]
pub struct NetworkStats {
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub sent_packets: u64,
    pub recv_packets: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub image_name: String,
    pub command_line: String,

    pub memory: Option<MemorySnapshot>,
    pub cpu: CpuStats,
    pub disk: DiskStats,
    pub network: NetworkStats,
}

impl From<&ProcessStarted> for ProcessEntry {
    fn from(e: &ProcessStarted) -> Self {
        Self {
            pid: e.pid,
            parent_pid: e.parent_pid,
            session_id: e.session_id,
            image_name: e.image_name.clone(),
            command_line: e.command_line.clone(),
            memory: None,
            cpu: CpuStats::default(),
            disk: DiskStats::default(),
            network: NetworkStats::default(),
        }
    }
}

impl From<ProcessStarted> for ProcessEntry {
    fn from(e: ProcessStarted) -> Self {
        Self {
            pid: e.pid,
            parent_pid: e.parent_pid,
            session_id: e.session_id,
            image_name: e.image_name,
            command_line: e.command_line,
            memory: None,
            cpu: CpuStats::default(),
            disk: DiskStats::default(),
            network: NetworkStats::default(),
        }
    }
}

pub struct ProcessTable {
    processes: HashMap<u32, ProcessEntry>,
    tid_to_pid: HashMap<u32, u32>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            tid_to_pid: HashMap::new(),
        }
    }

    pub fn apply(&mut self, change: StateChange) {
        match change {
            StateChange::ProcessStarted(e) | StateChange::ProcessRundown(e) => {
                self.processes.insert(e.pid, ProcessEntry::from(e));
            }
            StateChange::ProcessStopped(pid) => {
                self.processes.remove(&pid);
            }
            StateChange::ThreadStarted { pid, tid } => {
                self.tid_to_pid.insert(tid, pid);
            }
            StateChange::ThreadStopped { tid } => {
                self.tid_to_pid.remove(&tid);
            }
            StateChange::Memory(snap) => {
                if let Some(entry) = self.processes.get_mut(&snap.pid) {
                    entry.memory = Some(snap);
                }
            }
            StateChange::CpuUsage { pid, percent } => {
                if let Some(entry) = self.processes.get_mut(&pid) {
                    entry.cpu.total_percent = percent;
                }
            }
            StateChange::Disk(e) => {
                if let Some(entry) = self.processes.get_mut(&e.pid) {
                    match e.event_type {
                        DiskEventType::Read => {
                            entry.disk.read_bytes += e.transfer_size;
                            entry.disk.read_ops += 1;
                        }
                        DiskEventType::Write => {
                            entry.disk.write_bytes += e.transfer_size;
                            entry.disk.write_ops += 1;
                        }
                        DiskEventType::Flush => {}
                    }
                }
            }
            StateChange::Network(e) => {
                if let Some(entry) = self.processes.get_mut(&e.pid) {
                    match e.event_type {
                        NetworkEventType::Send => {
                            entry.network.sent_bytes += e.size as u64;
                            entry.network.sent_packets += 1;
                        }
                        NetworkEventType::Recv => {
                            entry.network.recv_bytes += e.size as u64;
                            entry.network.recv_packets += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn pid_for_tid(&self, tid: u32) -> Option<u32> {
        self.tid_to_pid.get(&tid).copied()
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.get(&pid)
    }

    pub fn snapshot(&self) -> Vec<&ProcessEntry> {
        self.processes.values().collect()
    }
}
