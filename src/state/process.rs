use fxhash::FxHashMap;

use crate::state::events::{MemorySnapshot, ProcessStarted, ProcessSignature, StateChange};

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
    pub image_path: String,
    /// Resolved by the enrichment pass; empty until then, and empty for
    /// anything whose name could not be resolved at all.
    pub display_name: String,
    pub command_line: Vec<String>,
    pub package_name: String,
    pub package_relative_app_id: String,

    pub signature: ProcessSignature,
    pub exited: bool,
    pub is_kernel_process: bool,
    pub is_windows_process: bool,
    pub console_host_pid: u32,

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
            image_path: String::new(),
            display_name: String::new(),
            command_line: e.command_line.clone(),
            package_name: e.package_full_name.clone(),
            package_relative_app_id: e.package_relative_app_id.clone(),
            signature: ProcessSignature::Unknown,
            exited: false,
            is_kernel_process: e.is_kernel_process,
            is_windows_process: e.is_kernel_process,
            console_host_pid: 0,
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
            image_path: String::new(),
            display_name: String::new(),
            command_line: e.command_line,
            package_name: e.package_full_name,
            package_relative_app_id: e.package_relative_app_id,
            signature: ProcessSignature::Unknown,
            exited: false,
            is_kernel_process: e.is_kernel_process,
            is_windows_process: e.is_kernel_process,
            console_host_pid: 0,
            memory: None,
            cpu: CpuStats::default(),
            disk: DiskStats::default(),
            network: NetworkStats::default(),
        }
    }
}

pub const IDLE_THREAD_ID: u32 = 0;
pub const IDLE_PROCESS_ID: u32 = 0;
pub const NO_PROCESS_ID: u32 = u32::MAX;

pub struct ProcessTable {
    processes: FxHashMap<u32, ProcessEntry>,
    tid_to_pid: FxHashMap<u32, u32>,
    samples: FxHashMap<u32, u64>,
    samples_unattributed: u64,
    samples_idle: u64,
    recently_stopped: FxHashMap<u32, u32>,


    last_fold: (u64, u64, u64),

    exited_last_window: Vec<u32>,

    passports: u32,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            processes: FxHashMap::default(),
            tid_to_pid: FxHashMap::default(),
            samples: FxHashMap::default(),
            samples_unattributed: 0,
            samples_idle: 0,
            recently_stopped: FxHashMap::default(),


            last_fold: (0, 0, 0),

            exited_last_window: Vec::new(),

            passports: 0,
        }
    }

    /// Moves whenever anything a process's passport (the protocol's
    /// ProcessInfo) is built from changes, or a process joins or leaves.
    pub fn passport_generation(&self) -> u32 {
        self.passports
    }

    fn passport_changed(&mut self) {
        self.passports = self.passports.wrapping_add(1);
    }

    pub fn apply(&mut self, change: StateChange) {
        match change {
            StateChange::ProcessStarted(e) | StateChange::ProcessRundown(e) => {
                self.processes.insert(e.pid, ProcessEntry::from(*e));
                self.passport_changed();
            }
            StateChange::ProcessEnriched(e) => {
                let e = *e;
                let Some(entry) = self.processes.get_mut(&e.pid) else {
                    return;
                };
                let is_windows_process = entry.is_kernel_process || e.is_windows_process;
                let changed = (!e.command_line.is_empty() && entry.command_line != e.command_line)
                    || entry.image_path != e.image_path
                    || entry.display_name != e.display_name
                    || entry.signature != e.signature
                    || entry.is_windows_process != is_windows_process
                    || entry.console_host_pid != e.console_host_pid;
                if !changed {
                    return;
                }
                if !e.command_line.is_empty() {
                    entry.command_line = e.command_line;
                }
                entry.image_path = e.image_path;
                entry.display_name = e.display_name;
                entry.signature = e.signature;
                entry.is_windows_process = is_windows_process;
                entry.console_host_pid = e.console_host_pid;
                self.passport_changed();
            }
            StateChange::ServicesSnapshot(_) => {}
            StateChange::ProcessStopped(pid) => {
                if let Some(entry) = self.processes.get_mut(&pid) {
                    entry.exited = true;
                }
            }
            StateChange::ThreadStarted { pid, tid } => {
                self.tid_to_pid.insert(tid, pid);
            }
            StateChange::ThreadStopped { tid } => {
                if let Some(pid) = self.tid_to_pid.remove(&tid) {
                    self.recently_stopped.insert(tid, pid);
                }
            }
            StateChange::Memory(snaps) => {
                for snap in snaps {
                    if let Some(entry) = self.processes.get_mut(&snap.pid) {
                        entry.memory = Some(snap);
                    }
                }
            }
            StateChange::Machine(_) => {}
            StateChange::CpuSamples(samples) => {
                for (key, count) in samples {
                    self.record_sample(key.tid, key.pid_hint, count);
                }
            }
            StateChange::Disk(deltas) => {
                for (tid, d) in deltas {
                    let Some(pid) = self.resolve_pid(tid, NO_PROCESS_ID) else {
                        continue;
                    };
                    if let Some(entry) = self.processes.get_mut(&pid) {
                        entry.disk.read_bytes += d.read_bytes;
                        entry.disk.read_ops += d.read_ops;
                        entry.disk.write_bytes += d.write_bytes;
                        entry.disk.write_ops += d.write_ops;
                    }
                }
            }
            StateChange::Network(deltas) => {
                for (pid, d) in deltas {
                    if let Some(entry) = self.processes.get_mut(&pid) {
                        entry.network.sent_bytes += d.tx_bytes;
                        entry.network.sent_packets += d.tx_packets;
                        entry.network.recv_bytes += d.rx_bytes;
                        entry.network.recv_packets += d.rx_packets;
                    }
                }
            }
        }
    }

    pub fn record_sample(&mut self, tid: u32, pid_hint: u32, count: u64) {
        if tid == IDLE_THREAD_ID {
            self.samples_idle += count;
            return;
        }

        match self.resolve_pid(tid, pid_hint) {
            Some(pid) => *self.samples.entry(pid).or_default() += count,
            None => {
                if pid_hint == IDLE_PROCESS_ID || pid_hint == NO_PROCESS_ID {
                    self.samples_idle += count;
                } else {
                    self.samples_unattributed += count;
                }
            }
        }
    }

    pub fn fold_samples(&mut self, attributable_percent: f32) {
        let total: u64 = self.samples.values().sum::<u64>() + self.samples_unattributed;

        for entry in self.processes.values_mut() {
            entry.cpu.total_percent = 0.0;
        }

        if total > 0 {
            for (pid, count) in &self.samples {
                if let Some(entry) = self.processes.get_mut(pid) {
                    entry.cpu.total_percent =
                        (*count as f64 / total as f64) * attributable_percent as f64;
                }
            }
        }

        self.last_fold = (
            self.samples.values().sum::<u64>(),
            self.samples_unattributed,
            self.samples_idle,
        );

        let mut removed = false;
        for pid in self.exited_last_window.drain(..) {
            removed |= self.processes.remove(&pid).is_some();
        }
        if removed {
            self.passport_changed();
        }
        self.exited_last_window = self
            .processes
            .values()
            .filter(|entry| entry.exited)
            .map(|entry| entry.pid)
            .collect();
        self.samples.clear();
        self.samples_unattributed = 0;
        self.samples_idle = 0;
        self.recently_stopped.clear();
    }

    pub fn sample_counts(&self) -> (u64, u64, u64) {
        self.last_fold
    }



    fn resolve_pid(&self, tid: u32, pid_hint: u32) -> Option<u32> {
        self.tid_to_pid
            .get(&tid)
            .or_else(|| self.recently_stopped.get(&tid))
            .copied()
            .or_else(|| {
                (pid_hint != IDLE_PROCESS_ID
                    && pid_hint != NO_PROCESS_ID
                    && self.processes.contains_key(&pid_hint))
                .then_some(pid_hint)
            })
    }

    #[cfg(test)]
    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.get(&pid)
    }

    pub fn len(&self) -> usize {
        self.processes.len()
    }

    pub fn entries(&self) -> impl Iterator<Item = &ProcessEntry> {
        self.processes.values()
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started(pid: u32) -> StateChange {
        StateChange::ProcessStarted(Box::new(crate::state::events::ProcessStarted {
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

    fn sample(t: &mut ProcessTable, tid: u32, pid_hint: u32, count: u64) {
        t.record_sample(tid, pid_hint, count);
    }

    fn table_with_threads() -> ProcessTable {
        let mut t = ProcessTable::new();
        t.apply(started(100));
        t.apply(started(200));
        t.apply(StateChange::ThreadStarted { pid: 100, tid: 1 });
        t.apply(StateChange::ThreadStarted { pid: 200, tid: 2 });
        t
    }

    #[test]
    fn samples_are_shared_out_of_the_attributable_time() {
        let mut t = table_with_threads();
        sample(&mut t, 1, 0, 30);
        sample(&mut t, 2, 0, 10);

        t.fold_samples(80.0);

        assert!((t.get(100).unwrap().cpu.total_percent - 60.0).abs() < 0.01);
        assert!((t.get(200).unwrap().cpu.total_percent - 20.0).abs() < 0.01);
    }

    #[test]
    fn samples_from_threads_nobody_claims_still_shrink_everyone_else() {
        let mut t = table_with_threads();
        sample(&mut t, 1, 100, 50);
        sample(&mut t, 999, 777, 50);

        t.fold_samples(100.0);

        assert!(
            (t.get(100).unwrap().cpu.total_percent - 50.0).abs() < 0.01,
            "an unattributed sample must not be redistributed to the survivors"
        );
    }

    #[test]
    fn a_process_that_burnt_nothing_this_window_drops_to_zero() {
        let mut t = table_with_threads();
        sample(&mut t, 1, 0, 10);
        t.fold_samples(100.0);
        assert!(t.get(100).unwrap().cpu.total_percent > 0.0);

        sample(&mut t, 2, 0, 10);
        t.fold_samples(100.0);

        assert_eq!(t.get(100).unwrap().cpu.total_percent, 0.0);
        assert!((t.get(200).unwrap().cpu.total_percent - 100.0).abs() < 0.01);
    }

    #[test]
    fn idle_samples_do_not_shrink_the_busy_processes() {
        let mut t = table_with_threads();
        sample(&mut t, 1, 0, 10);
        sample(&mut t, IDLE_THREAD_ID, 0, 90);

        t.fold_samples(100.0);

        assert!(
            (t.get(100).unwrap().cpu.total_percent - 100.0).abs() < 0.01,
            "idle is already out of the busy figure; counting it again halves everyone"
        );
    }

    #[test]
    fn a_sample_that_arrives_after_its_thread_died_still_finds_its_process() {
        let mut t = table_with_threads();
        t.apply(StateChange::ThreadStopped { tid: 1 });
        sample(&mut t, 1, 0, 10);

        t.fold_samples(100.0);

        assert!(
            (t.get(100).unwrap().cpu.total_percent - 100.0).abs() < 0.01,
            "samples and thread events come from separate sessions, so a stop can be applied first"
        );
    }

    #[test]
    fn an_unknown_thread_falls_back_to_the_process_the_event_was_charged_to() {
        let mut t = table_with_threads();
        sample(&mut t, 4242, 200, 10);

        t.fold_samples(100.0);

        assert!((t.get(200).unwrap().cpu.total_percent - 100.0).abs() < 0.01);
    }

    #[test]
    fn a_hint_pointing_at_nothing_is_not_trusted() {
        let mut t = table_with_threads();
        sample(&mut t, 4242, 777, 10);

        t.fold_samples(100.0);

        assert_eq!(t.get(100).unwrap().cpu.total_percent, 0.0);
        assert_eq!(t.get(200).unwrap().cpu.total_percent, 0.0);
    }

    #[test]
    fn a_process_that_died_this_window_still_gets_its_share() {
        let mut t = table_with_threads();
        t.apply(StateChange::ProcessStopped(100));
        sample(&mut t, 1, 100, 10);

        t.fold_samples(100.0);

        let dead = t.get(100).expect("the row survives the window it died in");
        assert!(dead.exited);
        assert!((dead.cpu.total_percent - 100.0).abs() < 0.01);
    }

    #[test]
    fn the_dead_are_gone_by_the_next_window() {
        let mut t = table_with_threads();
        t.apply(StateChange::ProcessStopped(100));
        t.fold_samples(100.0);
        assert!(t.get(100).is_some());

        t.fold_samples(100.0);
        assert!(t.get(100).is_none());
    }

    #[test]
    fn samples_taken_outside_any_process_do_not_shrink_the_processes() {
        let mut t = table_with_threads();
        sample(&mut t, 1, 100, 10);
        sample(&mut t, 7777, NO_PROCESS_ID, 90);

        t.fold_samples(100.0);

        assert!(
            (t.get(100).unwrap().cpu.total_percent - 100.0).abs() < 0.01,
            "idle and interrupt context are already out of the attributable figure"
        );
    }

    fn enriched(pid: u32, display_name: &str) -> StateChange {
        StateChange::ProcessEnriched(Box::new(crate::state::events::ProcessEnriched {
            pid,
            display_name: display_name.to_string(),
            ..Default::default()
        }))
    }

    fn disk_by_thread(tid: u32, write_bytes: u64) -> StateChange {
        let mut deltas = crate::state::events::DiskDeltas::default();
        deltas.insert(
            tid,
            crate::state::events::DiskDelta {
                write_bytes,
                write_ops: 1,
                ..Default::default()
            },
        );
        StateChange::Disk(deltas)
    }

    #[test]
    fn a_transfer_is_charged_to_the_process_of_the_issuing_thread() {
        let mut t = table_with_threads();
        t.apply(disk_by_thread(2, 4096));
        t.apply(disk_by_thread(2, 4096));

        assert_eq!(t.get(200).unwrap().disk.write_bytes, 8192);
        assert_eq!(t.get(200).unwrap().disk.write_ops, 2);
        assert_eq!(t.get(100).unwrap().disk.write_bytes, 0);
    }

    #[test]
    fn a_transfer_from_a_thread_that_just_exited_still_finds_its_process() {
        let mut t = table_with_threads();
        t.apply(StateChange::ThreadStopped { tid: 1 });
        t.apply(disk_by_thread(1, 512));
        assert_eq!(t.get(100).unwrap().disk.write_bytes, 512);
    }

    #[test]
    fn a_transfer_from_an_unknown_thread_is_charged_to_no_process() {
        let mut t = table_with_threads();
        t.apply(disk_by_thread(4242, 512));
        assert_eq!(t.get(100).unwrap().disk.write_bytes, 0);
        assert_eq!(t.get(200).unwrap().disk.write_bytes, 0);
    }

    #[test]
    fn a_memory_pass_leaves_the_disk_figures_alone() {
        let mut t = table_with_threads();
        t.apply(disk_by_thread(1, 512));
        t.apply(StateChange::Memory(vec![MemorySnapshot {
            pid: 100,
            working_set_bytes: 4096,
            ..Default::default()
        }]));
        assert_eq!(t.get(100).unwrap().disk.write_bytes, 512);
        assert_eq!(t.get(100).unwrap().memory.as_ref().unwrap().working_set_bytes, 4096);
    }

    #[test]
    fn a_network_batch_is_charged_per_process() {
        let mut t = table_with_threads();
        let mut deltas = crate::state::events::NetDeltas::default();
        deltas.insert(100, crate::state::events::NetDelta { rx_bytes: 10, tx_bytes: 20, rx_packets: 1, tx_packets: 2 });
        deltas.insert(777, crate::state::events::NetDelta { rx_bytes: 5, ..Default::default() });
        t.apply(StateChange::Network(deltas.clone()));
        t.apply(StateChange::Network(deltas));

        let n = &t.get(100).unwrap().network;
        assert_eq!((n.recv_bytes, n.sent_bytes, n.recv_packets, n.sent_packets), (20, 40, 2, 4));
        assert_eq!(t.get(200).unwrap().network.recv_bytes, 0);
    }

    #[test]
    fn a_start_moves_the_passport_generation() {
        let mut t = ProcessTable::new();
        let before = t.passport_generation();
        t.apply(started(100));
        assert_ne!(t.passport_generation(), before);
    }

    #[test]
    fn an_enrichment_moves_it_only_when_the_passport_changes() {
        let mut t = table_with_threads();
        t.apply(enriched(100, "Probe"));
        let named = t.passport_generation();

        t.apply(enriched(100, "Probe"));
        assert_eq!(t.passport_generation(), named, "nothing changed");

        t.apply(enriched(100, "Renamed"));
        assert_ne!(t.passport_generation(), named);
    }

    #[test]
    fn a_console_host_arriving_moves_it() {
        let mut t = table_with_threads();
        let before = t.passport_generation();
        t.apply(StateChange::ProcessEnriched(Box::new(crate::state::events::ProcessEnriched {
            pid: 100,
            console_host_pid: 4242,
            ..Default::default()
        })));
        assert_ne!(t.passport_generation(), before);
        assert_eq!(t.get(100).unwrap().console_host_pid, 4242);
    }

    #[test]
    fn an_enrichment_for_a_process_already_gone_moves_nothing() {
        let mut t = table_with_threads();
        let before = t.passport_generation();
        t.apply(enriched(999, "Ghost"));
        assert_eq!(t.passport_generation(), before);
    }

    #[test]
    fn a_stop_keeps_the_passport_until_the_row_is_removed() {
        let mut t = table_with_threads();
        let before = t.passport_generation();

        t.apply(StateChange::ProcessStopped(100));
        t.fold_samples(100.0);
        assert_eq!(t.passport_generation(), before, "the row is still listed");

        t.fold_samples(100.0);
        assert_ne!(t.passport_generation(), before, "the row left the list");
    }

    #[test]
    fn a_quiet_window_leaves_nobody_holding_stale_figures() {
        let mut t = table_with_threads();
        sample(&mut t, 1, 0, 10);
        t.fold_samples(100.0);

        t.fold_samples(0.0);

        assert_eq!(t.get(100).unwrap().cpu.total_percent, 0.0);
    }
}
