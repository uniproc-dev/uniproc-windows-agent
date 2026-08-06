mod sample;
mod vars;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::providers::machine::sample::{CpuTimes, PdhProcessorPerformance, sample_machine};
use crate::providers::provider::{LivePids, Provider};
use crate::sink::Sink;
use crate::state::events::StateChange;

pub struct MachineProvider {
    running: Arc<AtomicBool>,
    interval_ms: Arc<AtomicU64>,
}

impl MachineProvider {
    pub fn new(interval_ms: Arc<AtomicU64>) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            interval_ms,
        }
    }
}

impl Default for MachineProvider {
    fn default() -> Self {
        Self::new(Arc::new(AtomicU64::new(crate::settings::DEFAULT_INTERVAL_MS)))
    }
}

impl Provider for MachineProvider {
    fn start(&self, _: LivePids, sink: Sink) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let running = self.running.clone();
        let interval_ms = self.interval_ms.clone();

        std::thread::Builder::new()
            .name("machine-poller".into())
            .spawn(move || {
                let mut prev_cpu_times: Option<CpuTimes> = None;
                let mut pdh = PdhProcessorPerformance::open();
                let mut power_info = Vec::new();
                while running.load(Ordering::Relaxed) {
                    sink.emit(StateChange::Machine(sample_machine(
                        &mut prev_cpu_times,
                        pdh.as_mut(),
                        &mut power_info,
                    )));
                    let ms = interval_ms.load(Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(ms));
                }
            })
            .expect("failed to spawn machine-poller");

        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
