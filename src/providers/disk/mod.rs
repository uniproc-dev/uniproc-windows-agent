mod events;
mod vars;

use std::collections::HashMap;

use anyhow::Result;
use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_DISK_IO;

use crate::etw::router::KernelRouterBuilder;
use crate::providers::provider::Provider;
use crate::state::events::{DiskEvent, DiskEventType, StateChange};
use crate::etw::signatures::utils::parse;
use crate::providers::disk::events::{DiskIoTypeGroup1, DiskIoTypeGroup3};
use crate::providers::disk::vars::*;

struct PendingIrp {
    pid: u32,
    event_type: DiskEventType,
    transfer_size: u32,
    byte_offset: i64,
    disk_number: u32,
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
        let mut pending: HashMap<u64, PendingIrp> = HashMap::new();

        b.kernel_flags(EVENT_TRACE_FLAG_DISK_IO)
            .on(&[DISK_IO_TASK_GUID], move |record, data| {
                let opcode = record.EventHeader.EventDescriptor.Opcode;
                match opcode {
                    OPCODE_DISK_READ | OPCODE_DISK_WRITE => {
                        let g = parse::<DiskIoTypeGroup1>(data)?;
                        let event_type = if opcode == OPCODE_DISK_READ {
                            DiskEventType::Read
                        } else {
                            DiskEventType::Write
                        };
                        pending.insert(
                            g.irp,
                            PendingIrp {
                                pid: record.EventHeader.ProcessId,
                                event_type,
                                transfer_size: g.transfer_size,
                                byte_offset: g.byte_offset,
                                disk_number: g.disk_number,
                            },
                        );
                        None
                    }
                    OPCODE_DISK_COMPLETE => {
                        let g = parse::<DiskIoTypeGroup3>(data)?;
                        let irp = pending.remove(&g.irp)?;
                        Some(StateChange::Disk(DiskEvent {
                            pid: irp.pid,
                            event_type: irp.event_type,
                            transfer_size: irp.transfer_size as u64,
                            byte_offset: irp.byte_offset,
                            disk_number: irp.disk_number,
                            elapsed_time: g.high_res_response_time,
                        }))
                    }
                    _ => None,
                }
            });
        Ok(())
    }

    fn stop(&self) {}
}
