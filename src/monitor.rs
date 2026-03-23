use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use crate::collector::ProcessStatsCollector;

pub type SharedCollector = Arc<Mutex<ProcessStatsCollector>>;

pub fn run(stop: impl FnOnce()) -> Result<()> {
    let mut collector = ProcessStatsCollector::default();
    collector.start()?;

    let collector: SharedCollector = Arc::new(Mutex::new(collector));

    let tick_collector = collector.clone();
    std::thread::spawn(move || {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        let num_cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

        loop {
            std::thread::sleep(Duration::from_millis(1000));

            tick_collector.lock().unwrap().tick();

            sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing().with_cpu(),
            );

            let processes = {
                let mut c = tick_collector.lock().unwrap();
                let mut p = c.processes();
                p.sort_unstable_by(|a, b| {
                    b.cpu.total_percent
                        .partial_cmp(&a.cpu.total_percent)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                p
            };

            info!("=== top 5 processes ===");
            for p in processes.iter().take(5) {
                let sysinfo_cpu = sys
                    .process(sysinfo::Pid::from_u32(p.pid))
                    .map(|p| p.cpu_usage() / num_cores as f32)
                    .unwrap_or(0.0);
                let rss = p.memory.as_ref().map(|m| m.working_set_bytes / 1024).unwrap_or(0);
                info!(
                    "pid={} name={} our={:.1}% sysinfo={:.1}% rss={}kb disk_r={} disk_w={} net_r={} net_s={}",
                    p.pid,
                    p.image_name,
                    p.cpu.total_percent,
                    sysinfo_cpu,
                    rss,
                    p.disk.read_bytes,
                    p.disk.write_bytes,
                    p.network.recv_bytes,
                    p.network.sent_bytes,
                );
            }
        }
    });

    let node_collector = collector.clone();
    std::thread::spawn(move || {
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                if let Err(e) = crate::node::run(node_collector).await {
                    tracing::error!("node error: {e:#}");
                }
            });
    });

    info!("Uniproc monitor running");

    stop();

    info!("Shutting down…");
    collector.lock().unwrap().stop();
    Ok(())
}
