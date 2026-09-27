pub mod events;
pub mod network;
pub mod process;

use crate::snapshot::Row;
use crate::state::events::StateChange;
use crate::state::network::{NetworkCounters, NetworkStats};
use crate::state::process::{ProcessEntry, ProcessTable, Sighted};
use uniproc_agent_kit::Epoch;

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
    network: NetworkCounters,
    machine_totals: MachineTotals,
    epoch: Epoch,
}

impl SystemState {
    pub fn new() -> Self {
        Self {
            processes: ProcessTable::new(),
            network: NetworkCounters::default(),
            machine_totals: MachineTotals::default(),
            epoch: Epoch::new(),
        }
    }

    pub fn apply(&mut self, change: StateChange) {
        match change {
            StateChange::ProcessEnriched(e) => self.processes.enrich(*e),
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

    /// The processes become exactly `rows`; returns the rows new to it.
    pub fn reconcile<'a>(&mut self, rows: &'a [Row], sight: impl FnMut(&Row) -> Sighted) -> Vec<&'a Row> {
        let added = self.processes.reconcile(rows, sight);
        self.network.retain_listed(&self.processes);
        added
    }

    /// What the process sent and received since the agent first listed it.
    pub fn network(&self, pid: u32, sequence_number: u64) -> NetworkStats {
        self.network.get(pid, sequence_number)
    }

    /// Moves with every passport change. Never zero.
    pub fn processes_etag(&self) -> u64 {
        self.epoch.tag(self.processes.passport_generation())
    }

    pub fn machine_totals(&self) -> &MachineTotals {
        &self.machine_totals
    }

    pub fn process(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.get(pid)
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
    use crate::state::events::{DiskDelta, DiskDeltas};

    #[test]
    fn two_runs_start_from_different_tags() {
        assert_ne!(
            SystemState::new().processes_etag(),
            SystemState::new().processes_etag(),
            "a restarted agent must not hand out a tag a client still holds"
        );
    }

    #[test]
    fn a_process_showing_up_moves_the_tag() {
        let mut s = SystemState::new();
        let before = s.processes_etag();
        s.reconcile(
            &[Row {
                pid: 100,
                sequence_number: 1,
                ..Default::default()
            }],
            |_| Sighted::default(),
        );
        assert_ne!(s.processes_etag(), before);
    }

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
