mod processor_times;
mod sample;
mod vars;

use ntapi::ntpoapi::PROCESSOR_POWER_INFORMATION;

use crate::providers::machine::sample::{PdhProcessorPerformance, cpu_frequency_mhz, physical_memory};
use crate::sample::{MachineCpu, MachineDisk, MachineMetric, MachineMetrics, MachineNetwork, MachineSample};
use crate::state::MachineTotals;

/// Reads the machine's counters when a tick asks for them.
pub struct MachineProbe {
    pdh: Option<PdhProcessorPerformance>,
    power: Vec<PROCESSOR_POWER_INFORMATION>,
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
        }
    }

    /// The wanted groups; disk and network come from the ETW totals.
    pub fn sample(&mut self, wanted: MachineMetrics, totals: &MachineTotals) -> MachineSample {
        let mut sample = MachineSample::default();
        if wanted.contains(MachineMetric::Cpu) {
            sample.cpu = self.cpu();
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
        if wanted.contains(MachineMetric::Network) {
            sample.network = Some(MachineNetwork {
                rx_bytes: totals.net_rx_bytes,
                tx_bytes: totals.net_tx_bytes,
            });
        }
        sample
    }

    fn cpu(&mut self) -> Option<MachineCpu> {
        let times = match processor_times::read_totals() {
            Ok(times) => times,
            Err(error) => {
                tracing::warn!(%error, "could not read the processor times");
                return None;
            }
        };
        if self.pdh.is_none() {
            self.pdh = PdhProcessorPerformance::open();
        }
        let (max_mhz, current_mhz) = cpu_frequency_mhz(self.pdh.as_mut(), &mut self.power);
        Some(MachineCpu {
            idle_time: times.idle,
            kernel_time: times.kernel,
            user_time: times.user,
            interrupt_time: times.interrupt,
            dpc_time: times.dpc,
            max_mhz,
            current_mhz,
        })
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
        assert_eq!(sample.network.unwrap().rx_bytes, 5);
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
