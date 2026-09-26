use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use fxhash::FxHashMap;
use ntapi::ntpsapi::VM_COUNTERS_EX2;
use windows::Win32::{
    CloseHandle, HANDLE, NtQueryInformationProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::providers::memory::vars::PROCESS_VM_COUNTERS;
use crate::providers::provider::LivePids;
use crate::settings::{PollInterval, START_REACTION_SPACING};
use crate::state::events::MemorySnapshot;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct Opened {
    generation: u64,
    seen: u64,
    handle: Option<ProcessHandle>,
}

/// One handle per running process, kept across passes. A process that could
/// not be opened is remembered as such and not retried until its pid comes
/// back with a new start.
#[derive(Default)]
struct Handles {
    open: FxHashMap<u32, Opened>,
    live: Vec<(u32, u64)>,
    fresh: Vec<u32>,
    pass: u64,
}

impl Handles {
    /// Opens what is new to `live_pids`, reopens a pid that came back with a
    /// new start, closes what left; `fresh` lists the pids opened this time.
    fn sync(&mut self, live_pids: &LivePids) {
        self.pass += 1;
        self.fresh.clear();
        self.live.clear();
        self.live
            .extend(live_pids.iter().map(|entry| (*entry.key(), *entry.value())));

        for &(pid, generation) in &self.live {
            match self.open.get_mut(&pid) {
                Some(opened) if opened.generation == generation => opened.seen = self.pass,
                _ => {
                    let handle = crate::win::open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid)
                        .ok()
                        .map(ProcessHandle);
                    if handle.is_some() {
                        self.fresh.push(pid);
                    }
                    self.open.insert(
                        pid,
                        Opened {
                            generation,
                            seen: self.pass,
                            handle,
                        },
                    );
                }
            }
        }

        let pass = self.pass;
        self.open.retain(|_, opened| opened.seen == pass);
    }

    fn read(&self, now: u64, out: &mut Vec<MemorySnapshot>) {
        for (&pid, opened) in &self.open {
            read_one(pid, opened, now, out);
        }
    }

    fn read_fresh(&self, now: u64, out: &mut Vec<MemorySnapshot>) {
        for pid in &self.fresh {
            if let Some(opened) = self.open.get(pid) {
                read_one(*pid, opened, now, out);
            }
        }
    }

    fn unopened(&self) -> usize {
        self.open.values().filter(|o| o.handle.is_none()).count()
    }
}

fn read_one(pid: u32, opened: &Opened, now: u64, out: &mut Vec<MemorySnapshot>) {
    let Some(handle) = &opened.handle else {
        return;
    };
    let mut counters: VM_COUNTERS_EX2 = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            handle.0,
            PROCESS_VM_COUNTERS,
            &mut counters as *mut VM_COUNTERS_EX2 as *mut _,
            size_of::<VM_COUNTERS_EX2>() as u32,
            None,
        )
    };
    if status.is_ok() {
        out.push(snapshot(pid, &counters, now));
    }
}

fn snapshot(pid: u32, c: &VM_COUNTERS_EX2, now: u64) -> MemorySnapshot {
    let ex = &c.CountersEx;
    MemorySnapshot {
        pid,
        timestamp_ms: now,
        virtual_size_bytes: ex.VirtualSize as u64,
        peak_virtual_size_bytes: ex.PeakVirtualSize as u64,
        working_set_bytes: ex.WorkingSetSize as u64,
        peak_working_set_bytes: ex.PeakWorkingSetSize as u64,
        private_working_set_bytes: c.PrivateWorkingSetSize as u64,
        private_bytes: ex.PagefileUsage as u64,
        peak_private_bytes: ex.PeakPagefileUsage as u64,
        paged_pool_bytes: ex.QuotaPagedPoolUsage as u64,
        peak_paged_pool_bytes: ex.QuotaPeakPagedPoolUsage as u64,
        nonpaged_pool_bytes: ex.QuotaNonPagedPoolUsage as u64,
        peak_nonpaged_pool_bytes: ex.QuotaPeakNonPagedPoolUsage as u64,
        page_fault_count: ex.PageFaultCount,
    }
}

pub struct MemoryPoller {
    running: Arc<AtomicBool>,
    interval: Arc<PollInterval>,
}

impl MemoryPoller {
    pub fn new(interval: Arc<PollInterval>) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            interval,
        }
    }

    pub fn start<F>(&self, live_pids: LivePids, on_pass: F)
    where
        F: Fn(Vec<MemorySnapshot>) + Send + 'static,
    {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }

        let running = self.running.clone();
        let interval = self.interval.clone();

        std::thread::Builder::new()
            .name("memory-poller".into())
            .spawn(move || {
                let mut passes = 0u64;
                let mut micros_total = 0u64;
                let mut handles = Handles::default();
                let mut snaps: Vec<MemorySnapshot> = Vec::new();
                let started = Instant::now();
                let mut last_full = started;
                let mut next_full = started;
                let mut last_fresh = started;

                while running.load(Ordering::Relaxed) {
                    let pass_start = Instant::now();
                    if pass_start >= next_full {
                        handles.sync(&live_pids);
                        handles.read(now_ms(), &mut snaps);
                        let counted = snaps.len();
                        on_pass(std::mem::replace(&mut snaps, Vec::with_capacity(counted)));

                        passes += 1;
                        micros_total += pass_start.elapsed().as_micros() as u64;
                        if passes % 20 == 0 {
                            tracing::warn!(
                                pids = counted,
                                unopened = handles.unopened(),
                                passes,
                                avg_micros = micros_total / passes,
                                busy_percent_of_core = format!(
                                    "{:.2}",
                                    micros_total as f64 / started.elapsed().as_micros().max(1) as f64 * 100.0
                                ),
                                "memory poller"
                            );
                        }
                        last_full = pass_start;
                    } else {
                        let since = last_fresh.elapsed();
                        if since < START_REACTION_SPACING {
                            std::thread::sleep(START_REACTION_SPACING - since);
                        }
                        handles.sync(&live_pids);
                        handles.read_fresh(now_ms(), &mut snaps);
                        if !snaps.is_empty() {
                            on_pass(std::mem::take(&mut snaps));
                        }
                        last_fresh = Instant::now();
                    }
                    next_full = last_full + interval.period();
                    interval.wait_until(next_full);
                }
            })
            .expect("failed to spawn memory-poller thread");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.interval.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;

    fn live(entries: &[(u32, u64)]) -> LivePids {
        let map = DashMap::new();
        for &(pid, generation) in entries {
            map.insert(pid, generation);
        }
        Arc::new(map)
    }

    #[test]
    fn a_pass_reads_this_process_memory() {
        let mut handles = Handles::default();
        handles.sync(&live(&[(std::process::id(), 1)]));

        let mut snaps = Vec::new();
        handles.read(0, &mut snaps);
        let me = snaps
            .iter()
            .find(|s| s.pid == std::process::id())
            .expect("this process is read");
        assert!(me.working_set_bytes > 0);
        assert!(me.private_bytes > 0);
        assert!(me.private_working_set_bytes > 0);
        assert!(me.private_working_set_bytes <= me.working_set_bytes);
    }

    #[test]
    fn a_reused_pid_is_opened_again_and_a_gone_one_is_closed() {
        let me = std::process::id();
        let mut handles = Handles::default();

        handles.sync(&live(&[(me, 1)]));
        assert_eq!(handles.open[&me].generation, 1);

        handles.sync(&live(&[(me, 2)]));
        assert_eq!(handles.open[&me].generation, 2, "a new start of the same pid reopens");

        handles.sync(&live(&[]));
        assert!(handles.open.is_empty(), "a process that left the live set is closed");
    }

    #[test]
    fn only_newly_opened_processes_are_fresh() {
        let me = std::process::id();
        let mut handles = Handles::default();

        handles.sync(&live(&[(me, 1)]));
        assert_eq!(handles.fresh, vec![me]);
        let mut snaps = Vec::new();
        handles.read_fresh(0, &mut snaps);
        assert_eq!(snaps.len(), 1);

        handles.sync(&live(&[(me, 1), (0, 1)]));
        assert!(handles.fresh.is_empty(), "known or unopenable processes are not fresh");

        handles.sync(&live(&[(me, 2)]));
        assert_eq!(handles.fresh, vec![me], "a reused pid is fresh again");
    }

    #[test]
    fn a_process_that_cannot_be_opened_is_kept_without_a_handle() {
        let mut handles = Handles::default();
        handles.sync(&live(&[(0, 1)]));
        assert_eq!(handles.unopened(), 1, "Idle has no process to open");

        let mut snaps = Vec::new();
        handles.read(0, &mut snaps);
        assert!(snaps.is_empty());
    }
}
