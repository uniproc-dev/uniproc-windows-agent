mod sample;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::Mutex;

use crate::providers::provider::{LivePids, Provider};
use crate::sink::Sink;
use crate::state::events::StateChange;
use crate::providers::cpu::sample::{PrevEntry, sample};

pub struct CpuPollerProvider {
    prev: Arc<Mutex<HashMap<u32, PrevEntry>>>,
    last_tick: Arc<Mutex<Instant>>,
    interval_ms: Arc<AtomicU64>,
}

impl CpuPollerProvider {
    pub fn new(interval_ms: Arc<AtomicU64>) -> Self {
        Self {
            prev: Arc::new(Mutex::new(HashMap::new())),
            last_tick: Arc::new(Mutex::new(Instant::now())),
            interval_ms,
        }
    }
}

impl Default for CpuPollerProvider {
    fn default() -> Self {
        Self::new(Arc::new(AtomicU64::new(crate::settings::DEFAULT_INTERVAL_MS)))
    }
}

impl Provider for CpuPollerProvider {
    fn start(&self, live_pids: LivePids, sink: Sink) -> Result<()> {
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

                let pids: Vec<u32> = live_pids.iter().map(|e| *e.key()).collect();
                let mut prev = prev.lock();
                let mut changes = Vec::new();

                for pid in pids {
                    let cpu = unsafe { sample(pid, &mut prev, elapsed_ns, num_cores) };
                    changes.push(StateChange::CpuUsage { pid, percent: cpu });
                }

                sink.emit_all(changes);
            })
            .expect("failed to spawn cpu-poller");

        Ok(())
    }

    fn stop(&self) {}
}
