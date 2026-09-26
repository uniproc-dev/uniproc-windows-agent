use crate::settings::CollectorSettings;

pub mod bootstrap;
pub mod cpu_sampler;
pub mod display_name;
pub mod disk;
pub mod machine;
pub mod memory;
pub mod network;
pub mod process;
pub mod provider;
pub mod utils;

/// Every provider the core runs, sharing one enrichment queue.
pub fn all(signature_store: String, settings: &CollectorSettings) -> Vec<Box<dyn provider::Provider>> {
    let enrich_queue = crossbeam_channel::unbounded();
    vec![
        Box::new(cpu_sampler::CpuSamplerProvider::new()),
        Box::new(bootstrap::BootstrapProvider::new(Some(enrich_queue.0.clone()))),
        Box::new(disk::KernelDiskProvider::new()),
        Box::new(machine::MachineProvider::new(settings.cpu_interval_ms.clone())),
        Box::new(memory::MemoryPollerProvider::new(settings.memory_interval.clone())),
        Box::new(network::KernelNetworkProvider::new()),
        Box::new(process::KernelProcessProvider::with_queue(enrich_queue, signature_store)),
    ]
}
