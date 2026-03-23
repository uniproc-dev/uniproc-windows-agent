use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Clone)]
pub struct CollectorSettings {
    pub interval_ms: Arc<AtomicU64>,
}

impl Default for CollectorSettings {
    fn default() -> Self {
        Self {
            interval_ms: Arc::new(AtomicU64::new(1000)),
        }
    }
}

impl CollectorSettings {
    pub fn set_interval(&self, d: Duration) {
        self.interval_ms.store(d.as_millis() as u64, Ordering::Relaxed);
    }
}
