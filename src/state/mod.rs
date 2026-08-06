pub mod events;
pub mod process;

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
}

impl SystemState {
    pub fn new() -> Self {
        Self {
            processes: ProcessTable::new(),
            machine: None,
            machine_totals: MachineTotals::default(),
        }
    }

    pub fn apply(&mut self, change: StateChange) {
        match &change {
            StateChange::Machine(snap) => self.machine = Some(snap.clone()),
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

    pub fn snapshot(&self) -> Vec<ProcessEntry> {
        self.processes.snapshot().into_iter().cloned().collect()
    }
}

impl Default for SystemState {
    fn default() -> Self {
        Self::new()
    }
}
