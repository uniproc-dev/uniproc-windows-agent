use std::io::Cursor;
use std::sync::Arc;

use anyhow::Result;
use binrw::BinRead;
use parking_lot::Mutex;
use tracing::warn;
use windows::Win32::System::Diagnostics::Etw::*;

use crate::collector::provider::{ProcessMap, Provider};
use crate::collector::state::{NetworkEvent, NetworkEventType, NetworkProto, StateChange};
use crate::etw::kernel_session::KernelSessionRouter;
use crate::etw::signatures::defines::TcpIpTypeGroup4;
use crate::etw::signatures::utils::to_ip4;
use crate::etw::vars::*;

pub struct KernelNetworkProvider {
    queue: Arc<Mutex<Vec<StateChange>>>,
}

impl KernelNetworkProvider {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Provider for KernelNetworkProvider {
    fn start(&self, _processes: ProcessMap, kernel: Arc<KernelSessionRouter>) -> Result<()> {
        let queue = Arc::clone(&self.queue);

        kernel.register(move |record| {
            let provider = record.EventHeader.ProviderId;

            if provider != TCPIP_TASK_GUID && provider != UDPIP_TASK_GUID {
                return;
            }

            let opcode = record.EventHeader.EventDescriptor.Opcode;
            let data = unsafe {
                std::slice::from_raw_parts(
                    record.UserData as *const u8,
                    record.UserDataLength as usize,
                )
            };

            let (proto, event_type, is_v6) = match opcode {
                TCPIP_SEND => (NetworkProto::Tcp, NetworkEventType::Send, false),
                TCPIP_RECEIVE => (NetworkProto::Tcp, NetworkEventType::Recv, false),
                TCPIP_CONNECT => (NetworkProto::Tcp, NetworkEventType::Connect, false),
                TCPIP_ACCEPT => (NetworkProto::Tcp, NetworkEventType::Accept, false),
                UDPIP_SEND => (NetworkProto::Udp, NetworkEventType::Send, false),
                UDPIP_RECEIVE => (NetworkProto::Udp, NetworkEventType::Recv, false),
                _ => return,
            };

            let Ok(g) = TcpIpTypeGroup4::read(&mut Cursor::new(data)) else {
                return;
            };

            let event = NetworkEvent {
                pid: g.pid,
                proto,
                event_type,
                size: g.size,
                src_addr: to_ip4(g.src_addr),
                dst_addr: to_ip4(g.dst_addr),
                src_port: u16::from_be(g.src_port_be),
                dst_port: u16::from_be(g.dst_port_be),
            };

            queue.lock().push(StateChange::Network(event));
        });

        Ok(())
    }

    fn stop(&self) {}

    fn drain(&self) -> Vec<StateChange> {
        std::mem::take(&mut *self.queue.lock())
    }
}
