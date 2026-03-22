use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;

use crate::collector::ProcessStatsCollector;

pub const MEMORY_POLL_INTERVAL: Duration = Duration::from_secs(2);

pub type SharedCollector = Arc<Mutex<ProcessStatsCollector>>;

pub fn run(stop: impl FnOnce()) -> Result<()> {
    let mut collector = ProcessStatsCollector::default();
    collector.start()?;

    let collector = Arc::new(Mutex::new(collector));

    let tick_collector = Arc::clone(&collector);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(1000));
            let mut c = tick_collector.lock().unwrap();
            c.tick();
        }
    });

    let node_collector = Arc::clone(&collector);
    std::thread::spawn(move || {
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                if let Err(e) = crate::node::run(node_collector).await {
                    tracing::error!("node error: {e:#}");
                }
            });
    });

    info!(
        "Uniproc monitor running (ETW: process+disk+network | NT API: memory @{}s)",
        MEMORY_POLL_INTERVAL.as_secs()
    );

    stop();

    info!("Shutting down…");
    collector.lock().unwrap().stop();
    Ok(())
}
