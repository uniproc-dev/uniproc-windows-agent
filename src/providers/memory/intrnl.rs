use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::aligned::AlignedBuf;
use crate::settings::PollInterval;
use crate::providers::bootstrap::vars::{INITIAL_BUFFER_SIZE, STATUS_INFO_LENGTH_MISMATCH};
use crate::providers::provider::LivePids;
use crate::state::events::MemorySnapshot;
use ntapi::ntexapi::{
    SYSTEM_EXTENDED_THREAD_INFORMATION, SYSTEM_PROCESS_INFORMATION,
    SYSTEM_PROCESS_INFORMATION_EXTENSION,
};
use tracing::debug;
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};

const SYSTEM_FULL_PROCESS_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(148);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

unsafe fn shared_commit_of(start: *const u8, threads: usize, limit: usize) -> u64 {
    let offset = size_of::<SYSTEM_PROCESS_INFORMATION>()
        + threads * size_of::<SYSTEM_EXTENDED_THREAD_INFORMATION>();

    if offset + size_of::<SYSTEM_PROCESS_INFORMATION_EXTENSION>() > limit {
        return 0;
    }

    let ext = unsafe {
        start
            .add(offset)
            .cast::<SYSTEM_PROCESS_INFORMATION_EXTENSION>()
            .read_unaligned()
    };
    ext.SharedCommitCharge as u64
}

fn snap_from_entry(entry: &SYSTEM_PROCESS_INFORMATION, now: u64) -> MemorySnapshot {
    MemorySnapshot {
        pid: entry.UniqueProcessId as u32,
        timestamp_ms: now,
        virtual_size_bytes: entry.VirtualSize as u64,
        peak_virtual_size_bytes: entry.PeakVirtualSize as u64,
        working_set_bytes: entry.WorkingSetSize as u64,
        peak_working_set_bytes: entry.PeakWorkingSetSize as u64,
        private_working_set_bytes: unsafe { *entry.WorkingSetPrivateSize.QuadPart() } as u64,
        private_bytes: entry.PagefileUsage as u64,
        peak_private_bytes: entry.PeakPagefileUsage as u64,
        paged_pool_bytes: entry.QuotaPagedPoolUsage as u64,
        peak_paged_pool_bytes: entry.QuotaPeakPagedPoolUsage as u64,
        nonpaged_pool_bytes: entry.QuotaNonPagedPoolUsage as u64,
        peak_nonpaged_pool_bytes: entry.QuotaPeakNonPagedPoolUsage as u64,
        page_fault_count: entry.PageFaultCount,
        shared_commit_bytes: 0,
    }
}

fn query_all(buf: &mut AlignedBuf, out: &mut Vec<MemorySnapshot>) -> bool {
    out.clear();
    if buf.is_empty() {
        buf.resize(INITIAL_BUFFER_SIZE);
    }

    loop {
        let mut return_length = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_FULL_PROCESS_INFORMATION,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut return_length,
            )
        };

        if status.0 == STATUS_INFO_LENGTH_MISMATCH {
            buf.resize(return_length as usize + 64 * 1024);
            continue;
        }

        if status.is_err() {
            debug!("memory poll: NtQuerySystemInformation failed: {status:?}");
            return false;
        }

        let now = now_ms();
        let total = return_length as usize;
        let mut offset = 0usize;
        loop {
            let start = unsafe { buf.as_ptr().add(offset) };
            let entry = unsafe { start.cast::<SYSTEM_PROCESS_INFORMATION>().read_unaligned() };

            let limit = if entry.NextEntryOffset == 0 {
                total.saturating_sub(offset)
            } else {
                entry.NextEntryOffset as usize
            };

            let mut snap = snap_from_entry(&entry, now);
            snap.shared_commit_bytes =
                unsafe { shared_commit_of(start, entry.NumberOfThreads as usize, limit) };
            out.push(snap);

            if entry.NextEntryOffset == 0 {
                break;
            }
            offset += entry.NextEntryOffset as usize;
        }
        return true;
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

    pub fn start<F>(&self, _live_pids: LivePids, on_pass: F)
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
                let mut buf = AlignedBuf::zeroed(0);
                let mut snaps: Vec<MemorySnapshot> = Vec::new();

                while running.load(Ordering::Relaxed) {
                    let pass_start = std::time::Instant::now();
                    let mut counted = 0usize;
                    let mut snaps_shared = 0usize;
                    if query_all(&mut buf, &mut snaps) {
                        counted = snaps.len();
                        snaps_shared = snaps.iter().filter(|s| s.shared_commit_bytes > 0).count();
                        on_pass(std::mem::take(&mut snaps));
                    }
                    passes += 1;
                    micros_total += pass_start.elapsed().as_micros() as u64;
                    if passes % 20 == 0 {
                        tracing::warn!(
                            pids = counted,
                            with_shared = snaps_shared,
                            passes,
                            avg_micros = micros_total / passes,
                            busy_percent_of_core =
                                format!("{:.2}", micros_total as f64 / (passes as f64 * 1000.0) * 100.0),
                            "memory poller"
                        );
                    }
                    interval.wait();
                }
            })
            .expect("failed to spawn memory-poller thread");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.interval.wake();
    }
}

