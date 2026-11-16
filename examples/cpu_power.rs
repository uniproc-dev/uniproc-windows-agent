use std::time::Duration;

use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{MachineMetric, MetricSpec};

fn main() -> anyhow::Result<()> {
    let require = std::env::args().any(|arg| arg == "--require-reading");
    futures::executor::block_on(async {
        let agent = Agent::remote(Duration::from_secs(5)).await?;
        let mut watch = agent
            .watch(MetricSpec {
                machine: MachineMetric::Temperatures.into(),
                ..MetricSpec::idle(Duration::from_secs(1))
            })
            .await?;
        let mut readings = 0;
        for _ in 0..10 {
            let update = watch.next().await?;
            let watts = update.sample.machine.cpu_package_power_watts;
            if let Some(value) = watts {
                anyhow::ensure!(
                    value.is_finite() && value >= 0.0,
                    "invalid CPU package watts"
                );
                readings += 1;
            }
            println!(
                "at={} cpu_package_power_watts={watts:?}",
                update.sample.sampled_at
            );
        }
        anyhow::ensure!(!require || readings > 0, "CPU package power unavailable");
        Ok(())
    })
}
