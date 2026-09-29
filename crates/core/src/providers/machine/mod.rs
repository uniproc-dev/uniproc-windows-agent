mod adapters;
mod processor_times;
mod sample;
mod vars;

use ntapi::ntpoapi::PROCESSOR_POWER_INFORMATION;

use crate::providers::machine::adapters::NetworkAdapters;
use crate::providers::machine::processor_times::{ProcessorTimes, total};
use crate::providers::machine::sample::{PdhProcessorPerformance, cpu_frequency_mhz, physical_memory};
use crate::sample::{
    MachineCpu, MachineDisk, MachineMetric, MachineMetrics, MachineNetwork, MachineProcessor, MachineSample,
};
use crate::state::MachineTotals;

/// Reads the machine's counters when a tick asks for them.
pub struct MachineProbe {
    pdh: Option<PdhProcessorPerformance>,
    power: Vec<PROCESSOR_POWER_INFORMATION>,
    times: ProcessorTimes,
    adapters: NetworkAdapters,
}

impl Default for MachineProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl MachineProbe {
    pub fn new() -> Self {
        Self {
            pdh: None,
            power: Vec::new(),
            times: ProcessorTimes::new(),
            adapters: NetworkAdapters::default(),
        }
    }

    /// The wanted groups; disk and network come from the ETW totals.
    #[tracing::instrument(name = "machine", level = "debug", skip_all)]
    pub fn sample(&mut self, wanted: MachineMetrics, totals: &MachineTotals) -> MachineSample {
        let mut sample = MachineSample::default();
        if wanted.contains(MachineMetric::Cpu) || wanted.contains(MachineMetric::Processors) {
            match self.times.read() {
                Ok(processors) => {
                    if wanted.contains(MachineMetric::Processors) {
                        sample.processors = Some(processors.into());
                    }
                    if wanted.contains(MachineMetric::Cpu) {
                        let times = total(processors);
                        sample.cpu = Some(self.cpu(times));
                    }
                }
                Err(error) => tracing::warn!(%error, "could not read the processor times"),
            }
        }
        if wanted.contains(MachineMetric::Memory) {
            sample.memory = physical_memory();
        }
        if wanted.contains(MachineMetric::Disk) {
            sample.disk = Some(MachineDisk {
                read_ops: totals.disk_read_ops,
                write_ops: totals.disk_write_ops,
                read_bytes: totals.disk_read_bytes,
                write_bytes: totals.disk_write_bytes,
            });
        }
        if wanted.contains(MachineMetric::NetworkAdapters) {
            sample.network_adapters = Some(self.adapters.read());
        }
        if wanted.contains(MachineMetric::Network) {
            sample.network = Some(MachineNetwork {
                rx_bytes: totals.net_rx_bytes,
                tx_bytes: totals.net_tx_bytes,
            });
        }
        sample
    }

    fn cpu(&mut self, times: MachineProcessor) -> MachineCpu {
        if self.pdh.is_none() {
            self.pdh = PdhProcessorPerformance::open();
        }
        let (max_mhz, current_mhz) = cpu_frequency_mhz(self.pdh.as_mut(), &mut self.power);
        MachineCpu {
            idle_time: times.idle_time,
            kernel_time: times.kernel_time,
            user_time: times.user_time,
            interrupt_time: times.interrupt_time,
            dpc_time: times.dpc_time,
            max_mhz,
            current_mhz,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_wanted_groups_are_read() {
        let mut probe = MachineProbe::new();
        let totals = MachineTotals {
            net_rx_bytes: 5,
            ..Default::default()
        };
        let wanted: MachineMetrics = [MachineMetric::Memory, MachineMetric::Network].into_iter().collect();
        let sample = probe.sample(wanted, &totals);
        assert!(sample.cpu.is_none() && sample.disk.is_none());
        let memory = sample.memory.expect("memory");
        assert!(memory.total_physical > memory.available_physical);
        assert!(memory.commit_limit >= memory.total_physical / 2 && memory.committed <= memory.commit_limit);
        assert!(memory.committed > 0);
        assert_eq!(sample.network.unwrap().rx_bytes, 5);
        assert!(sample.processors.is_none());
    }

    #[test]
    fn the_processors_sum_to_the_cpu_group() {
        let mut probe = MachineProbe::new();
        let wanted: MachineMetrics = [MachineMetric::Cpu, MachineMetric::Processors].into_iter().collect();
        let sample = probe.sample(wanted, &MachineTotals::default());
        let (cpu, processors) = (sample.cpu.expect("cpu"), sample.processors.expect("processors"));
        let sum = total(&processors);
        assert_eq!(
            (sum.idle_time, sum.kernel_time, sum.user_time, sum.interrupt_time, sum.dpc_time),
            (cpu.idle_time, cpu.kernel_time, cpu.user_time, cpu.interrupt_time, cpu.dpc_time),
            "one read serves both groups"
        );
        assert!(processors.len() > 1);
    }

    #[test]
    fn the_cpu_group_carries_the_processor_times() {
        let mut probe = MachineProbe::new();
        let cpu = probe
            .sample([MachineMetric::Cpu].into_iter().collect(), &MachineTotals::default())
            .cpu
            .expect("cpu");
        assert!(cpu.kernel_time >= cpu.idle_time && cpu.user_time > 0);
        assert!(cpu.max_mhz > 0);
    }
}
