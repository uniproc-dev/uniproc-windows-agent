use std::time::Duration;

use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{MachineMetric, MetricSpec};

fn main() -> anyhow::Result<()> {
    futures::executor::block_on(async {
        let agent = Agent::remote(Duration::from_secs(5)).await?;
        let mut sampler = agent
            .subscribe(MetricSpec {
                machine: MachineMetric::Cpu.into(),
                ..MetricSpec::idle(Duration::from_secs(1))
            })
            .await?;
        let mut previous = None;
        for _ in 0..5 {
            let sample = sampler.next().await?;
            let name = sample
                .machine
                .cpu_name
                .ok_or_else(|| anyhow::anyhow!("service did not return a CPU name"))?;
            anyhow::ensure!(!name.is_empty(), "CPU name must not be empty");
            if let Some(previous) = &previous {
                anyhow::ensure!(previous == &name, "static CPU name changed between samples");
            }
            anyhow::ensure!(
                sample.machine.temperatures.is_none(),
                "CPU name probe did not request temperatures"
            );
            println!("cpu_name={name} cpu_counters={}", sample.machine.cpu.is_some());
            previous = Some(name);
        }
        Ok(())
    })
}
