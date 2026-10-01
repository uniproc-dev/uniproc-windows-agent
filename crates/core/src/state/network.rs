use rustc_hash::FxHashMap;

use crate::state::events::NetDeltas;
use crate::state::process::ProcessTable;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStats {
    pub sent_bytes: u64,
    pub recv_bytes: u64,
}

struct Counted {
    sequence_number: u64,
    stats: NetworkStats,
}

/// Bytes each listed process sent and received since the agent first saw it.
/// Kept apart from the passports: these move every batch, a passport rarely.
#[derive(Default)]
pub struct NetworkCounters {
    by_pid: FxHashMap<u32, Counted>,
}

impl NetworkCounters {
    /// Charges each delta to the process the table lists on that pid now;
    /// traffic of a pid the table does not list is dropped.
    pub fn charge(&mut self, deltas: &NetDeltas, table: &ProcessTable) {
        for (pid, d) in deltas {
            let Some(entry) = table.get(*pid) else {
                continue;
            };
            let counted = self.by_pid.entry(*pid).or_insert(Counted {
                sequence_number: entry.sequence_number,
                stats: NetworkStats::default(),
            });
            if counted.sequence_number != entry.sequence_number {
                *counted = Counted {
                    sequence_number: entry.sequence_number,
                    stats: NetworkStats::default(),
                };
            }
            counted.stats.sent_bytes += d.tx_bytes;
            counted.stats.recv_bytes += d.rx_bytes;
        }
    }

    /// Forgets the processes the table no longer lists.
    pub fn retain_listed(&mut self, table: &ProcessTable) {
        self.by_pid
            .retain(|pid, counted| table.get(*pid).is_some_and(|e| e.sequence_number == counted.sequence_number));
    }

    pub fn get(&self, pid: u32, sequence_number: u64) -> NetworkStats {
        self.by_pid
            .get(&pid)
            .filter(|counted| counted.sequence_number == sequence_number)
            .map_or_else(NetworkStats::default, |counted| counted.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Row;
    use crate::state::events::NetDelta;
    use crate::state::process::Sighted;

    fn row(pid: u32, sequence_number: u64) -> Row {
        Row {
            pid,
            sequence_number,
            ..Default::default()
        }
    }

    fn table(rows: &[Row]) -> ProcessTable {
        let mut t = ProcessTable::new();
        t.reconcile(rows, |_| Sighted::default(), |_| {});
        t
    }

    fn deltas(pid: u32, rx_bytes: u64, tx_bytes: u64) -> NetDeltas {
        let mut deltas = NetDeltas::default();
        deltas.insert(pid, NetDelta { rx_bytes, tx_bytes, ..Default::default() });
        deltas
    }

    #[test]
    fn a_network_batch_is_charged_per_process() {
        let t = table(&[row(100, 1), row(200, 2)]);
        let mut n = NetworkCounters::default();
        let mut batch = deltas(100, 10, 20);
        batch.insert(777, NetDelta { rx_bytes: 5, ..Default::default() });
        n.charge(&batch, &t);
        n.charge(&batch, &t);

        assert_eq!(n.get(100, 1), NetworkStats { sent_bytes: 40, recv_bytes: 20 });
        assert_eq!(n.get(200, 2), NetworkStats::default());
        assert_eq!(n.get(777, 0), NetworkStats::default(), "an unlisted pid is not counted");
    }

    #[test]
    fn a_reused_pid_starts_from_zero() {
        let mut t = table(&[row(100, 1)]);
        let mut n = NetworkCounters::default();
        n.charge(&deltas(100, 10, 0), &t);

        let next = [row(100, 9)];
        t.reconcile(&next, |_| Sighted::default(), |_| {});
        n.retain_listed(&t);
        assert_eq!(n.get(100, 9), NetworkStats::default());
        assert_eq!(n.get(100, 1), NetworkStats::default(), "the old process is forgotten");

        n.charge(&deltas(100, 3, 0), &t);
        assert_eq!(n.get(100, 9).recv_bytes, 3);
    }
}
