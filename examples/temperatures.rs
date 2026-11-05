use std::time::{Duration, Instant};
use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{MachineMetric, MetricSpec, TemperatureStatus};

fn main() -> anyhow::Result<()> {
    futures::executor::block_on(async {
        let agent = Agent::remote(Duration::from_secs(5)).await?;
        let mut sampler = agent
            .subscribe(MetricSpec {
                machine: MachineMetric::Temperatures.into(),
                ..MetricSpec::idle(Duration::from_secs(1))
            })
            .await?;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(15) {
            let sample = sampler.next().await?;
            let Some(temperatures) = sample.machine.temperatures else {
                anyhow::bail!("temperature group was not returned");
            };
            println!(
                "backend={:?} error={}",
                temperatures.status, temperatures.error
            );
            let mut ids = std::collections::HashSet::new();
            for device in &temperatures.devices {
                anyhow::ensure!(
                    !device.id.is_empty() && ids.insert(device.id.as_str()),
                    "device IDs must be unique and nonempty"
                );
                println!(
                    "device={} name={} category={:?} status={:?} error={}",
                    device.id, device.name, device.category, device.status, device.error
                );
                let mut sensors = std::collections::HashSet::new();
                for sensor in &device.sensors {
                    anyhow::ensure!(
                        !sensor.id.is_empty() && sensors.insert(sensor.id.as_str()),
                        "sensor IDs must be unique and nonempty"
                    );
                    anyhow::ensure!(
                        sensor.celsius.is_none_or(f64::is_finite),
                        "temperature must be finite"
                    );
                    println!(
                        "  sensor={} name={} celsius={:?}",
                        sensor.id, sensor.name, sensor.celsius
                    );
                }
            }
            if temperatures.status == TemperatureStatus::Available {
                anyhow::ensure!(
                    !temperatures.devices.is_empty(),
                    "live check expects discovered hardware"
                );
            }
        }
        Ok(())
    })
}
