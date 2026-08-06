use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub const DEFAULT_INTERVAL_MS: u64 = 1000;

#[derive(Clone)]
pub struct CollectorSettings {
    pub memory_interval_ms: Arc<AtomicU64>,
    pub cpu_interval_ms: Arc<AtomicU64>,
}

impl Default for CollectorSettings {
    fn default() -> Self {
        Self {
            memory_interval_ms: Arc::new(AtomicU64::new(DEFAULT_INTERVAL_MS)),
            cpu_interval_ms: Arc::new(AtomicU64::new(DEFAULT_INTERVAL_MS)),
        }
    }
}

impl CollectorSettings {
    pub fn set_memory_interval(&self, d: Duration) {
        self.memory_interval_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn set_cpu_interval(&self, d: Duration) {
        self.cpu_interval_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }
}
