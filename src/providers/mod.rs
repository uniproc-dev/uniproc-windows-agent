use crate::settings::CollectorSettings;
use crate::supervisor::Supervisor;

pub mod bootstrap;
pub mod cpu;
pub mod display_name;
pub mod disk;
pub mod machine;
pub mod memory;
pub mod network;
pub mod process;
pub mod provider;
mod utils;

impl Default for Supervisor {
    fn default() -> Supervisor {
        let settings = CollectorSettings::default();
        let enrich_queue = crossbeam_channel::unbounded();
        Supervisor::new(
            vec![
                Box::new(cpu::CpuPollerProvider::new(settings.cpu_interval_ms.clone())),
                Box::new(bootstrap::BootstrapProvider::new(Some(
                    enrich_queue.0.clone(),
                ))),
                Box::new(disk::KernelDiskProvider::new()),
                Box::new(machine::MachineProvider::new(settings.cpu_interval_ms.clone())),
                Box::new(memory::MemoryPollerProvider::new(
                    settings.memory_interval_ms.clone(),
                )),
                Box::new(network::KernelNetworkProvider::new()),
                Box::new(process::KernelProcessProvider::with_queue(enrich_queue)),
            ],
            Default::default(),
            settings,
        )
    }
}
