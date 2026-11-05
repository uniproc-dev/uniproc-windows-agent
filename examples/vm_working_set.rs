use std::time::{Duration, Instant};

use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{MetricSpec, NO_DATA_U64, ProcessMetric};

fn main() -> anyhow::Result<()> {
    let pid: u32 = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: vm_working_set <pid>"))?
        .parse()?;
    futures::executor::block_on(async {
        let agent = Agent::remote(Duration::from_secs(5)).await?;
        if let Agent::Remote(remote) = &agent {
            anyhow::ensure!(remote.can_vm_working_set(), "service does not support VmWorkingSet");
        }
        let mut sampler = agent
            .subscribe(MetricSpec {
                processes: ProcessMetric::WorkingSet | ProcessMetric::PrivateWorkingSet | ProcessMetric::VmWorkingSet,
                ..MetricSpec::idle(Duration::from_secs(1))
            })
            .await?;
        let started = Instant::now();
        let mut available = 0;
        while started.elapsed() < Duration::from_secs(30) {
            let sample = sampler.next().await?;
            let index = sample
                .pids
                .iter()
                .position(|value| *value == pid)
                .ok_or_else(|| anyhow::anyhow!("target process is not listed"))?;
            let at = |column: &Option<std::sync::Arc<[u64]>>| {
                column
                    .as_ref()
                    .and_then(|column| column.get(index))
                    .copied()
                    .filter(|value| *value != NO_DATA_U64)
            };
            let raw = at(&sample.columns.working_set);
            let corrected = at(&sample.columns.vm_working_set);
            println!(
                "pid={pid} sequence={} raw={raw:?} private={:?} vm_working_set={corrected:?}",
                sample.sequence_numbers[index],
                at(&sample.columns.private_working_set)
            );
            if let Some(value) = corrected {
                anyhow::ensure!(value > 0, "live VM should have resident pages");
                available += 1;
            }
        }
        anyhow::ensure!(
            available > 0,
            "VmWorkingSet remained unavailable throughout the live probe"
        );
        Ok(())
    })
}
