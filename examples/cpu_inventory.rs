use std::time::Duration;

use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{MachineMetric, MetricSpec};

fn main() -> anyhow::Result<()> {
    let allow_missing = std::env::args().any(|arg| arg == "--allow-missing");
    futures::executor::block_on(async {
        let agent = Agent::remote(Duration::from_secs(5)).await?;
        let mut sampler = agent
            .subscribe(MetricSpec {
                machine: MachineMetric::Cpu.into(),
                ..MetricSpec::idle(Duration::from_secs(1))
            })
            .await?;
        let mut uptime = None;
        for _ in 0..3 {
            let sample = sampler.next().await?;
            let machine = sample.machine;
            if !allow_missing {
                anyhow::ensure!(machine.system_stats.is_some(), "system statistics unavailable");
                anyhow::ensure!(machine.cpu_inventory.is_some(), "CPU inventory unavailable");
            }
            if let Some(stats) = machine.system_stats {
                if let Some(previous) = uptime {
                    anyhow::ensure!(stats.uptime_ms >= previous, "boot uptime went backwards");
                }
                uptime = Some(stats.uptime_ms);
            }
            println!(
                "cpu={:?} system_stats={:?} cpu_inventory={:?}",
                machine.cpu_name, machine.system_stats, machine.cpu_inventory
            );
        }
        Ok(())
    })
}
