use crate::settings::CollectorSettings;
pub use crate::supervisor::Supervisor;
use crate::supervisor::SupervisorConfig;

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

/// What one running agent names on the machine: its ETW sessions and its
/// signature store. Two agents with different profiles do not touch each
/// other; a second one with the same profile takes the first one's sessions.
pub struct Profile {
    pub session_namespace: Option<&'static str>,
    pub signature_store: &'static str,
}

pub const SERVICE: Profile = Profile {
    session_namespace: None,
    signature_store: "signature-cache",
};

pub const EMBEDDED: Profile = Profile {
    session_namespace: Some("Uniproc-Embedded-"),
    signature_store: "signature-cache-embedded",
};

pub const DEBUG: Profile = Profile {
    session_namespace: Some("Uniproc-Debug-"),
    signature_store: "signature-cache",
};

impl Default for Supervisor {
    fn default() -> Supervisor {
        supervisor(&SERVICE)
    }
}

pub fn supervisor(profile: &Profile) -> Supervisor {
    let settings = CollectorSettings::default();
    let enrich_queue = crossbeam_channel::unbounded();
    Supervisor::new(
        vec![
            Box::new(cpu_sampler::CpuSamplerProvider::new()),
            Box::new(bootstrap::BootstrapProvider::new(Some(
                enrich_queue.0.clone(),
            ))),
            Box::new(disk::KernelDiskProvider::new()),
            Box::new(machine::MachineProvider::new(settings.cpu_interval_ms.clone())),
            Box::new(memory::MemoryPollerProvider::new(
                settings.memory_interval.clone(),
            )),
            Box::new(network::KernelNetworkProvider::new()),
            Box::new(process::KernelProcessProvider::with_queue(
                enrich_queue,
                profile.signature_store,
            )),
        ],
        SupervisorConfig {
            session_namespace: profile.session_namespace.map(str::to_string),
            ..Default::default()
        },
        settings,
    )
}
