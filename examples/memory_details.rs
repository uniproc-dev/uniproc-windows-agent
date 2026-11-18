use std::time::Duration;
use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{MachineMetric, MetricSpec};

fn main() -> anyhow::Result<()> {
    futures::executor::block_on(async {
        let agent = Agent::remote(Duration::from_secs(5)).await?;
        let mut watch = agent.watch(MetricSpec {
            machine: MachineMetric::Memory.into(),
            ..MetricSpec::idle(Duration::from_secs(1))
        }).await?;
        for _ in 0..5 {
            let update = watch.next().await?;
            let memory = update.sample.machine.memory;
            println!("{}", serde_json::to_string(&memory)?);
            let memory = memory.ok_or_else(|| anyhow::anyhow!("memory unavailable"))?;
            anyhow::ensure!(memory.details.is_some(), "memory details unavailable");
            if let Some(d) = memory.details {
                if let (Some(cached), Some(standby), Some(modified)) = (d.cached, d.standby, d.modified) {
                    anyhow::ensure!(standby.checked_add(modified) == Some(cached), "inconsistent cached bytes");
                }
            }
        }
        Ok(())
    })
}
