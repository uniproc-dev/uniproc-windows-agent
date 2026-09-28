pub mod events;
pub mod network;
pub mod process;

use crate::model::ProcessState;
use crate::providers::process::ImageRequest;
use crate::report::Diff;
use crate::snapshot::Row;
use crate::state::events::{Image, StateChange};
use crate::state::network::{NetworkCounters, NetworkStats};
use crate::state::process::{ProcessTable, Sighted};

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

/// The core's current picture of the machine.
pub struct SystemState {
    processes: ProcessTable,
    network: NetworkCounters,
    machine_totals: MachineTotals,
}

impl SystemState {
    pub fn new() -> Self {
        Self {
            processes: ProcessTable::new(),
            network: NetworkCounters::default(),
            machine_totals: MachineTotals::default(),
        }
    }

    pub fn apply(&mut self, change: StateChange) {
        match change {
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
                self.network.charge(&deltas, &self.processes);
            }
        }
    }

    /// The processes become exactly `rows`, each new one read by `sight`;
    /// hands `ask` each image nobody asked a verdict for yet.
    #[tracing::instrument(name = "passports", level = "debug", skip_all)]
    pub fn reconcile(&mut self, rows: &[Row], sight: impl FnMut(&Row) -> Sighted, ask: impl FnMut(ImageRequest)) {
        self.processes.reconcile(rows, sight, ask);
        self.network.retain_listed(&self.processes);
    }

    /// Hands an image's verdict to every process running it.
    pub fn judge(&mut self, image: Image) {
        self.processes.judge(image);
    }

    /// Records a process's state as a sample saw it.
    pub fn observe(&mut self, state: ProcessState) {
        self.processes.observe(state);
    }

    /// Adds what changed since the last call to `diff`, in no order.
    pub fn take(&mut self, diff: &mut Diff) {
        self.processes.take(diff);
    }

    /// The images asked for and not judged yet.
    pub fn pending_images(&self) -> impl Iterator<Item = &str> {
        self.processes.pending()
    }

    /// What the process sent and received since the agent first listed it.
    pub fn network(&self, pid: u32, sequence_number: u64) -> NetworkStats {
        self.network.get(pid, sequence_number)
    }

    pub fn machine_totals(&self) -> &MachineTotals {
        &self.machine_totals
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
    use crate::state::events::{DiskDelta, DiskDeltas};

    #[test]
    fn disk_transfers_add_up_whichever_thread_issued_them() {
        let mut s = SystemState::new();
        let mut deltas = DiskDeltas::default();
        deltas.insert(1, DiskDelta { read_bytes: 10, read_ops: 1, ..Default::default() });
        deltas.insert(2, DiskDelta { write_bytes: 20, write_ops: 2, ..Default::default() });
        s.apply(StateChange::Disk(deltas));
        let t = s.machine_totals();
        assert_eq!((t.disk_read_bytes, t.disk_write_bytes, t.disk_write_ops), (10, 20, 2));
    }
}
