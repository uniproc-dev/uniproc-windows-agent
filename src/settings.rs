use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};

pub const DEFAULT_INTERVAL_MS: u64 = 1000;
pub const ATTACHED_MEMORY_INTERVAL_MS: u64 = 1000;
pub const IDLE_MEMORY_INTERVAL_MS: u64 = 2000;

/// A polling period whose waiter is woken as soon as the period changes.
pub struct PollInterval {
    ms: AtomicU64,
    wake_tx: Sender<()>,
    wake_rx: Receiver<()>,
}

impl PollInterval {
    pub fn new(ms: u64) -> Self {
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        Self {
            ms: AtomicU64::new(ms),
            wake_tx,
            wake_rx,
        }
    }

    pub fn set(&self, d: Duration) {
        self.ms.store(d.as_millis() as u64, Ordering::Relaxed);
        self.wake();
    }

    pub fn wake(&self) {
        let _ = self.wake_tx.try_send(());
    }

    /// Waits one period, returning early when woken.
    pub fn wait(&self) {
        let period = Duration::from_millis(self.ms.load(Ordering::Relaxed));
        let _ = self.wake_rx.recv_timeout(period);
    }
}

/// Parks until `deadline`, returning early once `running` is cleared and the
/// thread is unparked.
pub fn park_while(running: &AtomicBool, deadline: Instant) {
    while running.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        std::thread::park_timeout(deadline - now);
    }
}

#[derive(Clone)]
pub struct CollectorSettings {
    pub memory_interval: Arc<PollInterval>,
    pub cpu_interval_ms: Arc<AtomicU64>,
}

impl Default for CollectorSettings {
    fn default() -> Self {
        Self {
            memory_interval: Arc::new(PollInterval::new(IDLE_MEMORY_INTERVAL_MS)),
            cpu_interval_ms: Arc::new(AtomicU64::new(DEFAULT_INTERVAL_MS)),
        }
    }
}

impl CollectorSettings {
    pub fn set_memory_interval(&self, d: Duration) {
        self.memory_interval.set(d);
    }

    pub fn set_cpu_interval(&self, d: Duration) {
        self.cpu_interval_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn an_untouched_wait_lasts_the_whole_period() {
        let interval = PollInterval::new(150);
        let started = Instant::now();
        interval.wait();
        assert!(started.elapsed() >= Duration::from_millis(140));
    }

    #[test]
    fn changing_the_period_wakes_a_waiter_at_once() {
        let interval = Arc::new(PollInterval::new(10_000));
        let waiter = {
            let interval = interval.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                interval.wait();
                started.elapsed()
            })
        };

        std::thread::sleep(Duration::from_millis(50));
        interval.set(Duration::from_millis(1000));

        let waited = waiter.join().unwrap();
        assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    }

    #[test]
    fn wakes_that_pile_up_cost_one_early_pass() {
        let interval = PollInterval::new(150);
        interval.wake();
        interval.wake();
        interval.wake();

        let started = Instant::now();
        interval.wait();
        assert!(started.elapsed() < Duration::from_millis(100), "first wait was not woken");

        let started = Instant::now();
        interval.wait();
        assert!(
            started.elapsed() >= Duration::from_millis(140),
            "a second early return means wakes were not coalesced"
        );
    }

    #[test]
    fn a_park_lasts_until_the_deadline() {
        let running = AtomicBool::new(true);
        let started = Instant::now();
        park_while(&running, started + Duration::from_millis(120));
        assert!(started.elapsed() >= Duration::from_millis(120));
    }

    #[test]
    fn a_stop_ends_a_park_at_once() {
        let running = Arc::new(AtomicBool::new(true));
        let parked = {
            let running = running.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                park_while(&running, started + Duration::from_secs(30));
                started.elapsed()
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        running.store(false, Ordering::Relaxed);
        parked.thread().unpark();
        let waited = parked.join().unwrap();
        assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    }

    #[test]
    fn an_idle_agent_polls_memory_at_the_idle_rate() {
        let settings = CollectorSettings::default();
        assert_eq!(
            settings.memory_interval.ms.load(Ordering::Relaxed),
            IDLE_MEMORY_INTERVAL_MS
        );
    }
}
