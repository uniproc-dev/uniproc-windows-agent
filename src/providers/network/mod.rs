mod events;
mod vars;

use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_TRACE_FLAG_NETWORK_TCPIP};

use crate::etw::router::KernelRouterBuilder;
use crate::providers::provider::Provider;
use crate::state::events::{NetworkEvent, NetworkEventType, NetworkProto, StateChange};
use crate::etw::signatures::utils::{parse, to_ip4};
use crate::providers::network::events::{Ipv4Flow, Ipv6Flow};
use crate::providers::network::vars::*;

pub struct KernelNetworkProvider;

impl KernelNetworkProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KernelNetworkProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for KernelNetworkProvider {
    fn register(&self, b: &mut KernelRouterBuilder) -> Result<()> {
        b.kernel_flags(EVENT_TRACE_FLAG_NETWORK_TCPIP)
            .on(&[TCPIP_TASK_GUID, UDPIP_TASK_GUID], handle);
        Ok(())
    }

    fn stop(&self) {}
}

fn handle(record: &EVENT_RECORD, data: &[u8]) -> Option<StateChange> {
    let is_tcp = record.EventHeader.ProviderId == TCPIP_TASK_GUID;
    let opcode = record.EventHeader.EventDescriptor.Opcode;

    let (proto, event_type, is_v6) = match (is_tcp, opcode) {
        (true, TCPIP_SEND_V4) => (NetworkProto::Tcp, NetworkEventType::Send, false),
        (true, TCPIP_RECEIVE_V4) => (NetworkProto::Tcp, NetworkEventType::Recv, false),
        (true, TCPIP_CONNECT_V4) => (NetworkProto::Tcp, NetworkEventType::Connect, false),
        (true, TCPIP_ACCEPT_V4) => (NetworkProto::Tcp, NetworkEventType::Accept, false),
        (true, TCPIP_SEND_V6) => (NetworkProto::Tcp, NetworkEventType::Send, true),
        (true, TCPIP_RECEIVE_V6) => (NetworkProto::Tcp, NetworkEventType::Recv, true),
        (true, TCPIP_CONNECT_V6) => (NetworkProto::Tcp, NetworkEventType::Connect, true),
        (true, TCPIP_ACCEPT_V6) => (NetworkProto::Tcp, NetworkEventType::Accept, true),
        (false, UDPIP_SEND_V4) => (NetworkProto::Udp, NetworkEventType::Send, false),
        (false, UDPIP_RECEIVE_V4) => (NetworkProto::Udp, NetworkEventType::Recv, false),
        (false, UDPIP_SEND_V6) => (NetworkProto::Udp, NetworkEventType::Send, true),
        (false, UDPIP_RECEIVE_V6) => (NetworkProto::Udp, NetworkEventType::Recv, true),
        _ => return None,
    };

    let (pid, size, src_addr, dst_addr, src_port, dst_port) = if is_v6 {
        let f = parse::<Ipv6Flow>(data)?;
        (
            f.pid,
            f.size,
            to_ip4(f.src_addr),
            to_ip4(f.dst_addr),
            u16::from_be(f.src_port_be),
            u16::from_be(f.dst_port_be),
        )
    } else {
        let f = parse::<Ipv4Flow>(data)?;
        (
            f.pid,
            f.size,
            IpAddr::V4(Ipv4Addr::from(f.src_addr)),
            IpAddr::V4(Ipv4Addr::from(f.dst_addr)),
            u16::from_be(f.src_port_be),
            u16::from_be(f.dst_port_be),
        )
    };

    Some(StateChange::Network(NetworkEvent {
        pid,
        proto,
        event_type,
        size,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::network::events::tests::{v4_dump, v6_dump};
    use windows::Win32::System::Diagnostics::Etw::{EVENT_DESCRIPTOR, EVENT_HEADER};

    fn record(provider: windows::core::GUID, opcode: u8) -> EVENT_RECORD {
        EVENT_RECORD {
            EventHeader: EVENT_HEADER {
                ProviderId: provider,
                EventDescriptor: EVENT_DESCRIPTOR {
                    Opcode: opcode,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn network_event(change: Option<StateChange>) -> NetworkEvent {
        match change {
            Some(StateChange::Network(e)) => e,
            other => panic!("expected StateChange::Network, got {other:?}"),
        }
    }

    #[test]
    fn tcp_send_ipv4() {
        let e = network_event(handle(&record(TCPIP_TASK_GUID, TCPIP_SEND_V4), &v4_dump()));
        assert!(matches!(e.proto, NetworkProto::Tcp));
        assert!(matches!(e.event_type, NetworkEventType::Send));
        assert_eq!(e.pid, 1234);
        assert_eq!(e.size, 1460);
        assert_eq!(e.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(e.src_port, 8080);
        assert_eq!(e.dst_port, 443);
    }

    #[test]
    fn tcp_recv_ipv4() {
        let e = network_event(handle(&record(TCPIP_TASK_GUID, TCPIP_RECEIVE_V4), &v4_dump()));
        assert!(matches!(e.event_type, NetworkEventType::Recv));
    }

    #[test]
    fn udp_send_ipv4_is_not_tcp() {
        // Opcode 10 on UDPIP_TASK_GUID must not be classified as TCP.
        let e = network_event(handle(&record(UDPIP_TASK_GUID, UDPIP_SEND_V4), &v4_dump()));
        assert!(matches!(e.proto, NetworkProto::Udp));
        assert!(matches!(e.event_type, NetworkEventType::Send));
    }

    #[test]
    fn udp_recv_ipv6() {
        let e = network_event(handle(&record(UDPIP_TASK_GUID, UDPIP_RECEIVE_V6), &v6_dump()));
        assert!(matches!(e.proto, NetworkProto::Udp));
        assert!(matches!(e.event_type, NetworkEventType::Recv));
        assert_eq!(e.pid, 4321);
        assert_eq!(e.src_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(e.dst_port, 53);
    }

    #[test]
    fn tcp_connect_ipv6() {
        let e = network_event(handle(&record(TCPIP_TASK_GUID, TCPIP_CONNECT_V6), &v6_dump()));
        assert!(matches!(e.proto, NetworkProto::Tcp));
        assert!(matches!(e.event_type, NetworkEventType::Connect));
    }

    #[test]
    fn unknown_opcode_is_none() {
        assert!(handle(&record(TCPIP_TASK_GUID, 99), &v4_dump()).is_none());
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn network_events_flow_end_to_end() {
        use std::time::{Duration, Instant};

        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (sink, rx) = crate::sink::Sink::bounded(1024);
        let mut builder = crate::etw::router::KernelRouter::builder();
        KernelNetworkProvider::new()
            .register(&mut builder)
            .unwrap();
        let router = builder.start(sink).expect("router start");

        // Packets to TEST-NET-1 (192.0.2.0/24): emit kernel send events,
        // no answer or connectivity required.
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        for _ in 0..10 {
            let _ = sock.send_to(b"x", "192.0.2.1:53");
        }
        let _ = std::net::TcpStream::connect_timeout(
            &"192.0.2.1:80".parse().unwrap(),
            Duration::from_millis(500),
        );

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut events = 0;
        while Instant::now() < deadline {
            events += rx
                .try_iter()
                .filter(|c| matches!(c, StateChange::Network(_)))
                .count();
            if events > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        drop(router);
        assert!(events > 0, "no StateChange::Network received");
    }
}
