pub mod events;
pub mod process;

use std::collections::HashSet;

use crate::state::events::{DiskEventType, MachineSnapshot, NetworkEventType, StateChange};
use crate::state::process::{ProcessEntry, ProcessTable};

/// Machine-wide cumulative counters. Monotonic by construction: they only
/// accumulate ETW events and are not affected by process exits.
#[derive(Default, Debug, Clone)]
pub struct MachineTotals {
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_ops: u64,
    pub disk_write_ops: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

pub struct SystemState {
    processes: ProcessTable,
    machine: Option<MachineSnapshot>,
    machine_totals: MachineTotals,
    service_pids: HashSet<u32>,
}

impl SystemState {
    pub fn new() -> Self {
        Self {
            processes: ProcessTable::new(),
            machine: None,
            machine_totals: MachineTotals::default(),
            service_pids: HashSet::new(),
        }
    }

    pub fn apply(&mut self, change: StateChange) {
        match &change {
            StateChange::Machine(snap) => self.machine = Some(snap.clone()),
            StateChange::ServicePidsSnapshot(pids) => {
                self.service_pids = pids.iter().copied().collect();
            }
            StateChange::Disk(e) => match e.event_type {
                DiskEventType::Read => {
                    self.machine_totals.disk_read_bytes += e.transfer_size;
                    self.machine_totals.disk_read_ops += 1;
                }
                DiskEventType::Write => {
                    self.machine_totals.disk_write_bytes += e.transfer_size;
                    self.machine_totals.disk_write_ops += 1;
                }
                DiskEventType::Flush => {}
            },
            StateChange::Network(e) => match e.event_type {
                NetworkEventType::Send => self.machine_totals.net_tx_bytes += e.size as u64,
                NetworkEventType::Recv => self.machine_totals.net_rx_bytes += e.size as u64,
                _ => {}
            },
            _ => {}
        }
        self.processes.apply(change);
    }

    pub fn machine(&self) -> Option<&MachineSnapshot> {
        self.machine.as_ref()
    }

    pub fn machine_totals(&self) -> &MachineTotals {
        &self.machine_totals
    }

    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// By-reference view for report building: no per-request cloning of the
    /// whole table. Dynamic flags are resolved per entry by the caller.
    pub fn entries(&self) -> impl Iterator<Item = &ProcessEntry> {
        self.processes.entries()
    }

    pub fn is_service(&self, pid: u32) -> bool {
        self.service_pids.contains(&pid)
    }
}

impl Default for SystemState {
    fn default() -> Self {
        Self::new()
    }
}
