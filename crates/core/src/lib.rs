#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case, non_camel_case_types)]

mod aligned;
pub mod data;
mod etw;
mod model;
mod privileges;
mod probes;
mod process_events;
mod providers;
mod report;
mod sample;
mod schedule;
mod sink;
mod snapshot;
mod state;
mod supervisor;
mod win;

pub use model::{
    Architecture, DpiAwareness, ExtendedCfg, IoPriority, Isolation, Mitigations, ProcessPriority,
    ProcessState, StackProtection, UacVirtualization,
};
pub use report::{Diff, Health, Process, SessionHealth, SignatureStatus};
pub use sample::{
    Columns, Demand, GpuAdapter, GpuEngine, GpuEngineKind, MAX_INTERVAL, MIN_INTERVAL, MachineCpu, MachineDisk,
    MachineMemory, NetworkAdapter, ProcessGpuEngine,
    MachineMetric, MachineMetrics, MachineNetwork, MachineProcessor, MachineSample, MetricSpec, NO_DATA_U32,
    NO_DATA_U64, ProcessMetric, ProcessMetrics, Sample,
};
pub use etw::router::stop_leftover_sessions;
pub use process_events::{
    ProcessEvent, ProcessEventBatch, ProcessEventKind, ProcessEvents, ProcessEventsProvider, ProcessEventsWatch,
    ProcessExited, ProcessStarted,
};
pub use providers::provider::Provider;
pub use smol_str::SmolStr;
pub use supervisor::{Supervisor, SupervisorConfig};
pub use uniproc_agent_kit::{Epoch, Tagged};
