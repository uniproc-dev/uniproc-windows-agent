use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use parking_lot::Mutex;
#[cfg(feature = "service")]
use tracing::info;

#[cfg(feature = "service")]
use crate::embedded::Embedded;
use crate::settings::CollectorSettings;
use crate::state::SystemState;
use crate::supervisor::Supervisor;

pub type SharedSupervisor = Arc<Mutex<Supervisor>>;

/// A started supervisor and the thread that drains it; stops both when dropped.
pub struct Monitor {
    supervisor: SharedSupervisor,
    state: Arc<Mutex<SystemState>>,
    settings: CollectorSettings,
    tick_running: Arc<AtomicBool>,
    tick_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Monitor {
    pub fn start(mut supervisor: Supervisor) -> Result<Self> {
        // Without it, processes of other accounts (SYSTEM, DWM, UMFD, Hyper-V)
        // refuse even a limited query handle: no image path, signature or icon.
        // LocalSystem holds it enabled already; an elevated console must ask.
        if let Err(error) = crate::privileges::enable(windows::core::w!("SeDebugPrivilege")) {
            tracing::warn!(%error, "running without SeDebugPrivilege: other accounts' processes stay opaque");
        }

        supervisor.start()?;
        let tick_interval = supervisor.tick_interval();
        let state = supervisor.state();
        let settings = supervisor.settings();
        let supervisor: SharedSupervisor = Arc::new(Mutex::new(supervisor));

        // RPC and HTTP drain the Sink before they read; this drains it between
        // requests, and at once when the Sink reports it half full.
        let tick_running = Arc::new(AtomicBool::new(true));
        let tick_supervisor = supervisor.clone();
        let tick_running_thread = tick_running.clone();
        let tick_handle = std::thread::Builder::new()
            .name("supervisor-tick".into())
            .spawn(move || {
                let mut last_tick = std::time::Instant::now();
                while tick_running_thread.load(Ordering::Relaxed) {
                    std::thread::park_timeout(tick_interval);
                    let since = last_tick.elapsed();
                    if since < crate::settings::START_REACTION_SPACING {
                        std::thread::sleep(crate::settings::START_REACTION_SPACING - since);
                    }
                    tick_supervisor.lock().tick();
                    last_tick = std::time::Instant::now();
                }
            })?;
        supervisor.lock().set_drainer(tick_handle.thread().clone());

        Ok(Self {
            supervisor,
            state,
            settings,
            tick_running,
            tick_handle: Mutex::new(Some(tick_handle)),
        })
    }

    /// Stops the tick thread and the providers; reads after it see the last state.
    pub fn stop(&self) {
        self.tick_running.store(false, Ordering::Relaxed);
        if let Some(tick_handle) = self.tick_handle.lock().take() {
            tick_handle.thread().unpark();
            let _ = tick_handle.join();
        }
        self.supervisor.lock().stop();
    }

    #[cfg(feature = "service")]
    pub fn supervisor(&self) -> &SharedSupervisor {
        &self.supervisor
    }

    #[cfg(feature = "service")]
    pub fn state(&self) -> &Arc<Mutex<SystemState>> {
        &self.state
    }

    pub fn settings(&self) -> &CollectorSettings {
        &self.settings
    }

    /// Applies what the providers sent since the last tick, then hands over the state.
    pub fn read<R>(&self, f: impl FnOnce(&SystemState) -> R) -> R {
        self.supervisor.lock().tick();
        f(&self.state.lock())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(feature = "service")]
pub fn run(stop: impl FnOnce()) -> Result<()> {
    let agent = Arc::new(Embedded::from_monitor(Monitor::start(Supervisor::default())?));
    let monitor = agent.monitor();

    match crate::http::serve(monitor.state().clone(), monitor.supervisor().clone()) {
        Ok(access) => info!(
            url = access.url,
            access = %crate::http::access_path().display(),
            "state API listening"
        ),
        Err(error) => tracing::warn!(%error, "the state API did not start"),
    }

    let node_agent = agent.clone();
    std::thread::spawn(move || {
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                if let Err(e) = crate::rpc::run(node_agent).await {
                    tracing::error!("node error: {e:#}");
                }
            });
    });

    info!("Uniproc monitor running");

    stop();

    info!("Shutting down…");
    agent.monitor().stop();
    Ok(())
}
