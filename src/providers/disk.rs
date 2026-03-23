use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use parking_lot::Mutex;

use crate::collector::provider::{ProcessMap, Provider};
use crate::collector::state::{DiskEvent, DiskEventType, StateChange};
use crate::etw::kernel_session::KernelSessionRouter;
use crate::etw::vars::{DISK_IO_TASK_GUID};
use crate::providers::utils::to_user_data;

struct PendingIrp {
    pid: u32,
    event_type: DiskEventType,
    transfer_size: u32,
    byte_offset: i64,
    disk_number: u32,
}

pub struct KernelDiskProvider {
    queue: Arc<Mutex<Vec<StateChange>>>,
}

impl KernelDiskProvider {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Provider for KernelDiskProvider {
    fn start(&self, _processes: ProcessMap, kernel: Arc<KernelSessionRouter>) -> Result<()> {
        let queue = Arc::clone(&self.queue);
        let pending: Arc<Mutex<HashMap<u64, PendingIrp>>> = Arc::new(Mutex::new(HashMap::new()));

        kernel.register(move |record| {
            if record.EventHeader.ProviderId != DISK_IO_TASK_GUID {
                return;
            }
            let opcode = record.EventHeader.EventDescriptor.Opcode;
            let Some(data) = to_user_data(record) else {
                return;
            };

            // match opcode {
            //     OPCODE_DISK_READ | OPCODE_DISK_WRITE => {
            //         let Ok(g) = DiskIoTypeGroup1::read(&mut Cursor::new(data)) else {
            //             warn!("Disk: failed to parse TypeGroup1");
            //             return;
            //         };
            //         let etype = if opcode == OPCODE_DISK_READ {
            //             DiskEventType::Read
            //         } else {
            //             DiskEventType::Write
            //         };
            //         pending.lock().insert(
            //             g.irp,
            //             PendingIrp {
            //                 pid: record.EventHeader.ProcessId,
            //                 event_type: etype,
            //                 transfer_size: g.transfer_size,
            //                 byte_offset: g.byte_offset,
            //                 disk_number: g.disk_number,
            //             },
            //         );
            //     }
            //     OPCODE_DISK_COMPLETE => {
            //         let Ok(g) = DiskIoTypeGroup3::read(&mut Cursor::new(data)) else {
            //             warn!("Disk: failed to parse TypeGroup3");
            //             return;
            //         };
            //         let Some(irp) = pending.lock().remove(&g.irp) else {
            //             return;
            //         };
            //         queue.lock().push(StateChange::Disk(DiskEvent {
            //             pid: irp.pid,
            //             event_type: irp.event_type,
            //             transfer_size: irp.transfer_size as u64,
            //             byte_offset: irp.byte_offset,
            //             disk_number: irp.disk_number,
            //             elapsed_time: g.high_res_response_time,
            //         }));
            //     }
            //     _ => {}
            // }
        });

        Ok(())
    }

    fn stop(&self) {}

    fn drain(&self) -> Vec<StateChange> {
        std::mem::take(&mut *self.queue.lock())
    }
}
