use crate::collector::settings::CollectorSettings;
use crate::collector::ProcessStatsCollector;

pub mod bootstrap;
pub mod cpu;
pub mod disk;
pub mod memory;
pub mod network;
pub mod process;
mod utils;

impl Default for ProcessStatsCollector {
    fn default() -> ProcessStatsCollector {
        let settings = CollectorSettings::default();
        Self::new(
            vec![
                Box::new(cpu::CpuPollerProvider::new(settings.cpu_interval_ms.clone())),
                Box::new(bootstrap::BootstrapProvider::new()),
                Box::new(disk::KernelDiskProvider::new()),
                Box::new(memory::MemoryPollerProvider::new(settings.memory_interval_ms.clone())),
                Box::new(network::KernelNetworkProvider::new()),
                Box::new(process::KernelProcessProvider::new()),
            ],
            Default::default(),
            settings,
        )
    }
}
