pub mod counters;
mod events;
mod vars;

use std::time::Instant;

use anyhow::Result;
use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_PROFILE;

use crate::etw::router::KernelRouterBuilder;
use crate::etw::signatures::utils::parse;
use crate::providers::cpu_sampler::counters::{SampleBatch, SampleKey};
use crate::providers::cpu_sampler::events::SampledProfile;
use crate::providers::cpu_sampler::vars::*;
use crate::providers::provider::Provider;
use crate::state::events::StateChange;

#[derive(Default)]
pub struct CpuSamplerProvider;

impl CpuSamplerProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Provider for CpuSamplerProvider {
    fn register(&self, b: &mut KernelRouterBuilder) -> Result<()> {
        let mut batch = SampleBatch::new(FLUSH_ENTRIES, FLUSH_EVENTS, FLUSH_AGE);

        b.kernel_flags(EVENT_TRACE_FLAG_PROFILE).on(
            &[PERF_INFO_TASK_GUID],
            move |record, data| -> Option<StateChange> {
                if record.EventHeader.EventDescriptor.Opcode != OPCODE_SAMPLED_PROFILE {
                    return None;
                }

                let s = parse::<SampledProfile>(data)?;
                batch
                    .record(
                        SampleKey {
                            tid: s.thread_id,
                            pid_hint: record.EventHeader.ProcessId,
                        },
                        s.count.max(1) as u64,
                        Instant::now(),
                    )
                    .map(StateChange::CpuSamples)
            },
        );
        Ok(())
    }

    fn stop(&self) {}
}
