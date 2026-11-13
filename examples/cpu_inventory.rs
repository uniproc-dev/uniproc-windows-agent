use std::time::Duration;

use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{MachineMetric, MetricSpec};

fn main() -> anyhow::Result<()> {
    let allow_missing = std::env::args().any(|arg| arg == "--allow-missing");
    let require_details = std::env::args().any(|arg| arg == "--require-details");
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
            if require_details {
                let details = machine.cpu_inventory.as_ref().and_then(|v|v.details.as_ref()).ok_or_else(||anyhow::anyhow!("CPU details unavailable"))?;
                anyhow::ensure!(details.vendor.is_some(),"CPU vendor unavailable");
                anyhow::ensure!(details.family.is_some() && details.model.is_some() && details.stepping.is_some(),"CPU signature unavailable");
                anyhow::ensure!(details.instruction_sets.is_some(),"CPU instruction set check unavailable");
                anyhow::ensure!(details.instruction_sets_semantics == uniproc_windows_agent::api::CpuInstructionSetSemantics::OsUsable,"unexpected instruction set semantics");
            }
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
