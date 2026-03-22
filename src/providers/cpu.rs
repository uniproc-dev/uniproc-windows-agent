use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::Mutex;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::collector::provider::{ProcessMap, Provider};
use crate::collector::state::StateChange;
use crate::etw::kernel_session::KernelSessionRouter;

struct PrevEntry {
    kernel: u64,
    user: u64,
}

pub struct CpuPollerProvider {
    queue: Arc<Mutex<Vec<StateChange>>>,
    prev: Arc<Mutex<HashMap<u32, PrevEntry>>>,
    last_tick: Arc<Mutex<Instant>>,
    interval_ms: Arc<AtomicU64>,
}

impl CpuPollerProvider {
    pub fn new(interval_ms: Arc<AtomicU64>) -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
            prev: Arc::new(Mutex::new(HashMap::new())),
            last_tick: Arc::new(Mutex::new(Instant::now())),
            interval_ms,
        }
    }
}

impl Default for CpuPollerProvider {
    fn default() -> Self {
        Self::new(Arc::new(AtomicU64::new(1000)))
    }
}

impl Provider for CpuPollerProvider {
    fn start(&self, processes: ProcessMap, _kernel: Arc<KernelSessionRouter>) -> Result<()> {
        let queue = self.queue.clone();
        let prev = self.prev.clone();
        let last_tick = self.last_tick.clone();
        let interval_ms = self.interval_ms.clone();
        let num_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(1);

        std::thread::Builder::new()
            .name("cpu-poller".into())
            .spawn(move || loop {
                let ms = interval_ms.load(Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(ms));

                let elapsed_ns = {
                    let mut t = last_tick.lock();
                    let e = t.elapsed().as_nanos() as u64;
                    *t = Instant::now();
                    e
                };

                if elapsed_ns == 0 {
                    continue;
                }

                let pids: Vec<u32> = processes.iter().map(|e| *e.key()).collect();
                let mut prev = prev.lock();
                let mut changes = Vec::new();

                for pid in pids {
                    let cpu = unsafe { sample(pid, &mut prev, elapsed_ns, num_cores) };
                    changes.push(StateChange::CpuUsage { pid, percent: cpu });
                }

                queue.lock().extend(changes);
            })
            .expect("failed to spawn cpu-poller");

        Ok(())
    }

    fn stop(&self) {}

    fn drain(&self) -> Vec<StateChange> {
        std::mem::take(&mut *self.queue.lock())
    }
}

unsafe fn sample(pid: u32, prev: &mut HashMap<u32, PrevEntry>, elapsed_ns: u64, num_cores: u64) -> f64 {
    let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
        Ok(h) => h,
        Err(_) => return 0.0,
    };

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
    let _ = CloseHandle(handle);

    if ok.is_err() {
        return 0.0;
    }

    let k = (kernel.dwHighDateTime as u64) << 32 | kernel.dwLowDateTime as u64;
    let u = (user.dwHighDateTime as u64) << 32 | user.dwLowDateTime as u64;
    let total = k + u;

    let delta = match prev.get(&pid) {
        Some(e) => total.saturating_sub(e.kernel + e.user),
        None => {
            prev.insert(pid, PrevEntry { kernel: k, user: u });
            return 0.0;
        }
    };

    prev.insert(pid, PrevEntry { kernel: k, user: u });

    (delta as f64 / (elapsed_ns / 100) as f64 * 100.0 / num_cores as f64).min(100.0)
}
