use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::Mutex;
use tracing::info;

use crate::supervisor::Supervisor;

pub type SharedSupervisor = Arc<Mutex<Supervisor>>;

pub fn run(stop: impl FnOnce()) -> Result<()> {
    let mut supervisor = Supervisor::default();
    supervisor.start()?;
    let tick_interval = supervisor.tick_interval();

    let supervisor: SharedSupervisor = Arc::new(Mutex::new(supervisor));

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

    // Drains the Sink independently of RPC traffic — GetReport alone isn't
    // enough to keep the bounded channel from filling up under load.
    let tick_running = Arc::new(AtomicBool::new(true));
    let tick_supervisor = supervisor.clone();
    let tick_running_thread = tick_running.clone();
    let tick_handle = std::thread::Builder::new()
        .name("supervisor-tick".into())
        .spawn(move || {
            while tick_running_thread.load(Ordering::Relaxed) {
                std::thread::sleep(tick_interval);
                tick_supervisor.lock().tick();
            }
        })?;

    info!("Uniproc monitor running");

    stop();

    info!("Shutting down…");
    tick_running.store(false, Ordering::Relaxed);
    let _ = tick_handle.join();
    supervisor.lock().stop();
    Ok(())
}
