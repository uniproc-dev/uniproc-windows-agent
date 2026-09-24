use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::Mutex;
use tracing::info;

use crate::supervisor::Supervisor;

pub type SharedSupervisor = Arc<Mutex<Supervisor>>;

pub fn run(stop: impl FnOnce()) -> Result<()> {
    // Without it, processes of other accounts (SYSTEM, DWM, UMFD, Hyper-V)
    // refuse even a limited query handle: no image path, signature or icon.
    // LocalSystem holds it enabled already; an elevated console must ask.
    if let Err(error) = crate::privileges::enable(windows::core::w!("SeDebugPrivilege")) {
        tracing::warn!(%error, "running without SeDebugPrivilege: other accounts' processes stay opaque");
    }

    let mut supervisor = Supervisor::default();
    supervisor.start()?;
    let tick_interval = supervisor.tick_interval();

    let state = supervisor.state();
    let supervisor: SharedSupervisor = Arc::new(Mutex::new(supervisor));

    match crate::http::serve(state, supervisor.clone()) {
        Ok(access) => info!(
            url = access.url,
            access = %crate::http::access_path().display(),
            "state API listening"
        ),
        Err(error) => tracing::warn!(%error, "the state API did not start"),
    }

    let node_supervisor = supervisor.clone();
    std::thread::spawn(move || {
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                if let Err(e) = crate::rpc::run(node_supervisor).await {
                    tracing::error!("node error: {e:#}");
                }
            });
    });

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

    info!("Uniproc monitor running");

    stop();

    info!("Shutting down…");
    tick_running.store(false, Ordering::Relaxed);
    tick_handle.thread().unpark();
    let _ = tick_handle.join();
    supervisor.lock().stop();
    Ok(())
}
