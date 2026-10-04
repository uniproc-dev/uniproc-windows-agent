mod events;
mod vars;

use anyhow::Result;
use uniproc_etw::Event;

use crate::bindings::EVENT_TRACE_FLAG_DISK_IO;

use crate::etw::router::{Batch, KernelRouterBuilder};
use crate::etw::vars::BATCH_WINDOW;
use crate::providers::provider::Provider;
use crate::state::events::{DiskDeltas, DiskEvent, DiskEventType, StateChange};
use crate::etw::signatures::utils::parse;
use crate::providers::disk::events::DiskIoTypeGroup1;
use crate::providers::disk::vars::*;

fn event(event: &Event<'_>) -> Option<(u32, DiskEvent)> {
    let data = event.user_data();
    let event_type = match event.opcode() {
        OPCODE_DISK_READ => DiskEventType::Read,
        OPCODE_DISK_WRITE => DiskEventType::Write,
        _ => return None,
    };
    let g = parse::<DiskIoTypeGroup1>(data)?;
    Some((
        g.issuing_thread_id,
        DiskEvent {
            event_type,
            transfer_size: g.transfer_size as u64,
        },
    ))
}

#[derive(Default)]
struct DiskBatch(DiskDeltas);

impl Batch for DiskBatch {
    fn add(&mut self, read: &Event<'_>) {
        if let Some((tid, e)) = event(read) {
            self.0.entry(tid).or_default().add(&e);
        }
    }

    fn take(&mut self) -> Option<StateChange> {
        (!self.0.is_empty()).then(|| StateChange::Disk(std::mem::take(&mut self.0)))
    }
}

pub struct KernelDiskProvider;

impl KernelDiskProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KernelDiskProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for KernelDiskProvider {
    fn register(&self, b: &mut KernelRouterBuilder) -> Result<()> {
        b.kernel_flags(EVENT_TRACE_FLAG_DISK_IO).batched(
            &[DISK_IO_TASK_GUID],
            BATCH_WINDOW,
            DiskBatch::default(),
        );
        Ok(())
    }

    fn stop(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::disk::events::tests::group1_dump;
    use uniproc_etw::{Header, OwnedEvent};

    fn record(opcode: u8) -> OwnedEvent {
        let header = Header {
            provider: DISK_IO_TASK_GUID.to_u128(),
            opcode,
            ..Header::default()
        };
        OwnedEvent::new(header, group1_dump().to_vec())
    }

    #[test]
    fn a_batch_sums_reads_and_writes_and_ignores_the_rest() {
        let mut b = DiskBatch::default();
        b.add(&record(OPCODE_DISK_READ).event());
        b.add(&record(OPCODE_DISK_WRITE).event());
        b.add(&record(OPCODE_DISK_WRITE).event());
        b.add(&record(14).event());

        match b.take() {
            Some(StateChange::Disk(d)) => assert_eq!(
                d.get(&99),
                Some(&crate::state::events::DiskDelta {
                    read_bytes: 4096,
                    write_bytes: 8192,
                    read_ops: 1,
                    write_ops: 2,
                }),
                "keyed by the issuing thread the dump carries"
            ),
            other => panic!("expected a disk batch, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_batch_hands_over_nothing() {
        let mut b = DiskBatch::default();
        assert!(b.take().is_none());
        b.add(&record(14).event());
        assert!(b.take().is_none(), "an opcode that is not a transfer adds nothing");
        b.add(&record(OPCODE_DISK_READ).event());
        assert!(b.take().is_some());
        assert!(b.take().is_none(), "a handed over batch starts empty");
    }
}
