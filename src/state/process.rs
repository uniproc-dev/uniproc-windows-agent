use std::collections::HashMap;

use crate::state::events::{
    DiskEventType, MemorySnapshot, NetworkEventType, ProcessStarted, StateChange,
};

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
    pub command_line: Vec<String>,
    pub package_name: String,
    pub package_relative_app_id: String,

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
            package_name: e.package_full_name.clone(),
            package_relative_app_id: e.package_relative_app_id.clone(),
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
            package_name: e.package_full_name,
            package_relative_app_id: e.package_relative_app_id,
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
            StateChange::ProcessCommandLine { pid, command_line } => {
                if let Some(entry) = self.processes.get_mut(&pid) {
                    entry.command_line = command_line;
                }
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
            StateChange::Machine(_) => {}
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

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}
