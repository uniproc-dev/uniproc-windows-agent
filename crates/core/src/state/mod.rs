pub mod events;
pub mod process;

use crate::state::events::{MachineSnapshot, StateChange};
use crate::state::process::{ProcessEntry, ProcessTable};
use crate::tag::Epoch;

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
    epoch: Epoch,
}

impl SystemState {
    pub fn new() -> Self {
        Self {
            processes: ProcessTable::new(),
            machine: None,
            machine_totals: MachineTotals::default(),
            epoch: Epoch::new(),
        }
    }

    pub fn apply(&mut self, change: StateChange) {
        match &change {
            StateChange::Machine(snap) => {
                let attributable =
                    (snap.cpu_percent - snap.cpu_interrupt_percent - snap.cpu_dpc_percent).max(0.0);
                self.machine = Some(MachineSnapshot::clone(snap));
                self.processes.fold_samples(attributable);
            }
            StateChange::Disk(deltas) => {
                for d in deltas.values() {
                    self.machine_totals.disk_read_bytes += d.read_bytes;
                    self.machine_totals.disk_read_ops += d.read_ops;
                    self.machine_totals.disk_write_bytes += d.write_bytes;
                    self.machine_totals.disk_write_ops += d.write_ops;
                }
            }
            StateChange::Network(deltas) => {
                for d in deltas.values() {
                    self.machine_totals.net_rx_bytes += d.rx_bytes;
                    self.machine_totals.net_tx_bytes += d.tx_bytes;
                }
            }
            _ => {}
        }
        self.processes.apply(change);
    }

    /// Moves with every passport change. Never zero.
    pub fn processes_etag(&self) -> u64 {
        self.epoch.tag(self.processes.passport_generation())
    }

    pub fn machine(&self) -> Option<&MachineSnapshot> {
        self.machine.as_ref()
    }

    pub fn sample_counts(&self) -> (u64, u64, u64) {
        self.processes.sample_counts()
    }

    pub fn machine_totals(&self) -> &MachineTotals {
        &self.machine_totals
    }

    pub fn entries(&self) -> impl Iterator<Item = &ProcessEntry> {
        self.processes.entries()
    }
}

impl Default for SystemState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::events::ProcessStarted;

    fn started(pid: u32) -> StateChange {
        StateChange::ProcessStarted(Box::new(ProcessStarted {
            pid,
            parent_pid: 0,
            session_id: 0,
            image_name: format!("p{pid}.exe"),
            command_line: Vec::new(),
            package_full_name: String::new(),
            package_relative_app_id: String::new(),
            is_kernel_process: false,
        }))
    }

    #[test]
    fn two_runs_start_from_different_tags() {
        assert_ne!(
            SystemState::new().processes_etag(),
            SystemState::new().processes_etag(),
            "a restarted agent must not hand out a tag a client still holds"
        );
    }

    #[test]
    fn a_process_starting_moves_the_tag() {
        let mut s = SystemState::new();
        let before = s.processes_etag();
        s.apply(started(100));
        assert_ne!(s.processes_etag(), before);
    }
}
