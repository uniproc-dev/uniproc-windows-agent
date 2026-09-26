use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use uniproc_windows_core::{CollectorSettings, Report, Supervisor, SupervisorConfig};

/// The longest a report waits when the core has nothing new.
const PERIOD: Duration = Duration::from_secs(1);

/// The shortest gap between two reports, so a burst of changes costs a handful.
const SPACING: Duration = Duration::from_millis(50);

/// The core on a thread of its own: it reports as soon as the core has
/// something new, at least once a period, and hands every report over.
/// Stops the core when dropped.
pub struct Monitor {
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Monitor {
    /// Returns once the core runs and its first report has been handed over.
    pub fn start(
        config: SupervisorConfig,
        settings: CollectorSettings,
        mut publish: impl FnMut(Arc<Report>) + Send + 'static,
    ) -> Result<Self> {
        let running = Arc::new(AtomicBool::new(true));
        let (started, outcome) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("core".into())
            .spawn({
                let running = running.clone();
                move || {
                    let mut supervisor = Supervisor::new(config, settings);
                    if let Err(error) = supervisor.start() {
                        let _ = started.send(Err(error));
                        return;
                    }
                    publish(supervisor.tick());
                    let _ = started.send(Ok(()));

                    let mut last = Instant::now();
                    loop {
                        std::thread::park_timeout(PERIOD);
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }
                        let since = last.elapsed();
                        if since < SPACING {
                            std::thread::sleep(SPACING - since);
                        }
                        publish(supervisor.tick());
                        last = Instant::now();
                    }
                }
            })?;

        let outcome = outcome
            .recv()
            .unwrap_or_else(|_| Err(anyhow!("the core's thread ended before it started")));
        match outcome {
            Ok(()) => Ok(Self {
                running,
                thread: Some(thread),
            }),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}
