use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::providers::memory::vars::{PROCESS_VM_COUNTERS, PROCESS_VM_COUNTERS2, STATUS_SUCCESS};
use crate::providers::provider::LivePids;
use crate::state::events::MemorySnapshot;
use anyhow::{Result, bail};
use ntapi::ntpsapi::NtQueryInformationProcess;
use tracing::debug;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct VmCountersEx {
    PeakVirtualSize: usize,
    VirtualSize: usize,
    PageFaultCount: u32,
    _pad: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
    PrivateUsage: usize,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct VmCountersEx2 {
    base: VmCountersEx,
    PrivateWorkingSetSize: usize,
    SharedCommitUsage: usize,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub unsafe fn query_process_memory(pid: u32) -> Result<MemorySnapshot> {
    let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
    let result = do_query(handle, pid);
    let _ = CloseHandle(handle);
    result
}

fn do_query(handle: HANDLE, pid: u32) -> Result<MemorySnapshot> {
    let mut ret_len: u32 = 0;
    let handle = handle.0 as *const _ as *mut _;

    let mut ex2 = VmCountersEx2::default();
    let status2 = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_VM_COUNTERS2,
            &mut ex2 as *mut _ as *mut _,
            core::mem::size_of::<VmCountersEx2>() as u32,
            &mut ret_len,
        )
    };

    if status2 == STATUS_SUCCESS {
        return Ok(snap_from_ex2(pid, &ex2));
    }

    let mut ex = VmCountersEx::default();
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_VM_COUNTERS,
            &mut ex as *mut _ as *mut _,
            core::mem::size_of::<VmCountersEx>() as u32,
            &mut ret_len,
        )
    };

    if status == STATUS_SUCCESS {
        return Ok(snap_from_ex(pid, &ex));
    }

    bail!(
        "NtQueryInformationProcess failed for pid={pid}: \
         class65={:#010x} class3={:#010x}",
        status2 as u32,
        status as u32
    )
}

fn snap_from_ex(pid: u32, ex: &VmCountersEx) -> MemorySnapshot {
    MemorySnapshot {
        pid,
        timestamp_ms: now_ms(),
        virtual_size_bytes: ex.VirtualSize as u64,
        peak_virtual_size_bytes: ex.PeakVirtualSize as u64,
        working_set_bytes: ex.WorkingSetSize as u64,
        peak_working_set_bytes: ex.PeakWorkingSetSize as u64,
        private_working_set_bytes: 0,
        private_bytes: ex.PrivateUsage as u64,
        peak_private_bytes: ex.PeakPagefileUsage as u64,
        paged_pool_bytes: ex.QuotaPagedPoolUsage as u64,
        peak_paged_pool_bytes: ex.QuotaPeakPagedPoolUsage as u64,
        nonpaged_pool_bytes: ex.QuotaNonPagedPoolUsage as u64,
        peak_nonpaged_pool_bytes: ex.QuotaPeakNonPagedPoolUsage as u64,
        page_fault_count: ex.PageFaultCount,
        shared_commit_bytes: 0,
    }
}

fn snap_from_ex2(pid: u32, ex2: &VmCountersEx2) -> MemorySnapshot {
    let mut snap = snap_from_ex(pid, &ex2.base);
    snap.private_working_set_bytes = ex2.PrivateWorkingSetSize as u64;
    snap.shared_commit_bytes = ex2.SharedCommitUsage as u64;
    snap
}

pub struct MemoryPoller {
    running: Arc<AtomicBool>,
    interval_ms: Arc<AtomicU64>,
}

impl MemoryPoller {
    pub fn new(interval_ms: Arc<AtomicU64>) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            interval_ms,
        }
    }

    pub fn start<F>(&self, live_pids: LivePids, on_snapshot: F)
    where
        F: Fn(MemorySnapshot) + Send + 'static,
    {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }

        let running = self.running.clone();
        let interval_ms = self.interval_ms.clone();

        std::thread::Builder::new()
            .name("memory-poller".into())
            .spawn(move || unsafe {
                while running.load(Ordering::Relaxed) {
                    for entry in live_pids.iter() {
                        let pid = *entry.key();
                        match query_process_memory(pid) {
                            Ok(snap) => on_snapshot(snap),
                            Err(e) => debug!(pid, "memory poll: {e:#}"),
                        }
                    }
                    let ms = interval_ms.load(Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(ms));
                }
            })
            .expect("failed to spawn memory-poller thread");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
