mod events;
mod vars;

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use crate::bindings::{EVENT_RECORD, EVENT_TRACE_FLAG_NETWORK_TCPIP};

use crate::etw::router::{Batch, KernelRouterBuilder};
use crate::etw::vars::BATCH_WINDOW;
use crate::providers::provider::Provider;
use crate::state::events::{NetDeltas, NetworkEvent, NetworkEventType, StateChange};
use crate::etw::signatures::utils::parse;
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
        b.kernel_flags(EVENT_TRACE_FLAG_NETWORK_TCPIP).batched(
            &[TCPIP_TASK_GUID, UDPIP_TASK_GUID],
            BATCH_WINDOW,
            NetBatch::default(),
        );
        Ok(())
    }

    fn stop(&self) {}
}

#[derive(Default)]
struct NetBatch(NetDeltas);

impl Batch for NetBatch {
    fn add(&mut self, record: &EVENT_RECORD, data: &[u8]) {
        if let Some(e) = event(record, data) {
            self.0.entry(e.pid).or_default().add(&e);
        }
    }

    fn take(&mut self) -> Option<StateChange> {
        (!self.0.is_empty()).then(|| StateChange::Network(std::mem::take(&mut self.0)))
    }
}

fn event(record: &EVENT_RECORD, data: &[u8]) -> Option<NetworkEvent> {
    let is_tcp = record.EventHeader.ProviderId == TCPIP_TASK_GUID;
    let opcode = record.EventHeader.EventDescriptor.Opcode;

    let (event_type, is_v6) = match (is_tcp, opcode) {
        (true, TCPIP_SEND_V4) => (NetworkEventType::Send, false),
        (true, TCPIP_RECEIVE_V4) => (NetworkEventType::Recv, false),
        (true, TCPIP_CONNECT_V4) => (NetworkEventType::Connect, false),
        (true, TCPIP_ACCEPT_V4) => (NetworkEventType::Accept, false),
        (true, TCPIP_SEND_V6) => (NetworkEventType::Send, true),
        (true, TCPIP_RECEIVE_V6) => (NetworkEventType::Recv, true),
        (true, TCPIP_CONNECT_V6) => (NetworkEventType::Connect, true),
        (true, TCPIP_ACCEPT_V6) => (NetworkEventType::Accept, true),
        (false, UDPIP_SEND_V4) => (NetworkEventType::Send, false),
        (false, UDPIP_RECEIVE_V4) => (NetworkEventType::Recv, false),
        (false, UDPIP_SEND_V6) => (NetworkEventType::Send, true),
        (false, UDPIP_RECEIVE_V6) => (NetworkEventType::Recv, true),
        _ => return None,
    };

    let (pid, size, loopback) = if is_v6 {
        let f = parse::<Ipv6Flow>(data)?;
        let loopback = [f.dst_addr, f.src_addr].into_iter().any(|a| Ipv6Addr::from(a).to_canonical().is_loopback());
        (f.pid, f.size, loopback)
    } else {
        let f = parse::<Ipv4Flow>(data)?;
        let loopback = [f.dst_addr, f.src_addr].into_iter().any(|a| Ipv4Addr::from(a).is_loopback());
        (f.pid, f.size, loopback)
    };

    Some(NetworkEvent {
        pid,
        event_type,
        size,
        loopback,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::network::events::tests::{v4_dump, v6_dump};
    use crate::bindings::{EVENT_DESCRIPTOR, EVENT_HEADER};

    fn record(provider: windows_core::GUID, opcode: u8) -> EVENT_RECORD {
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

    fn network_event(parsed: Option<NetworkEvent>) -> NetworkEvent {
        parsed.expect("a network event")
    }

    #[test]
    fn a_batch_sums_traffic_per_process() {
        let mut b = NetBatch::default();
        b.add(&record(TCPIP_TASK_GUID, TCPIP_SEND_V4), &v4_dump());
        b.add(&record(TCPIP_TASK_GUID, TCPIP_SEND_V4), &v4_dump());
        b.add(&record(TCPIP_TASK_GUID, TCPIP_RECEIVE_V4), &v4_dump());
        b.add(&record(UDPIP_TASK_GUID, UDPIP_RECEIVE_V6), &v6_dump());
        b.add(&record(TCPIP_TASK_GUID, TCPIP_CONNECT_V6), &v6_dump());

        let Some(StateChange::Network(deltas)) = b.take() else {
            panic!("expected a network batch");
        };
        let tcp = deltas[&1234];
        assert_eq!((tcp.tx_bytes, tcp.tx_packets, tcp.rx_bytes, tcp.rx_packets), (2920, 2, 1460, 1));
        let udp = deltas[&4321];
        assert_eq!((udp.tx_packets, udp.rx_packets), (0, 1), "a connect carries no traffic");
        assert!(b.take().is_none(), "a handed over batch starts empty");
    }

    #[test]
    fn tcp_send_ipv4() {
        let e = network_event(event(&record(TCPIP_TASK_GUID, TCPIP_SEND_V4), &v4_dump()));
        assert!(matches!(e.event_type, NetworkEventType::Send));
        assert_eq!(e.pid, 1234);
        assert_eq!(e.size, 1460);
    }

    #[test]
    fn tcp_recv_ipv4() {
        let e = network_event(event(&record(TCPIP_TASK_GUID, TCPIP_RECEIVE_V4), &v4_dump()));
        assert!(matches!(e.event_type, NetworkEventType::Recv));
    }

    #[test]
    fn udp_recv_ipv6() {
        let e = network_event(event(&record(UDPIP_TASK_GUID, UDPIP_RECEIVE_V6), &v6_dump()));
        assert!(matches!(e.event_type, NetworkEventType::Recv));
        assert_eq!(e.pid, 4321);
        assert_eq!(e.size, 40);
    }

    #[test]
    fn tcp_connect_ipv6() {
        let e = network_event(event(&record(TCPIP_TASK_GUID, TCPIP_CONNECT_V6), &v6_dump()));
        assert!(matches!(e.event_type, NetworkEventType::Connect));
    }

    #[test]
    fn traffic_to_a_loopback_address_is_loopback() {
        let send_v4 = record(TCPIP_TASK_GUID, TCPIP_SEND_V4);
        let send_v6 = record(TCPIP_TASK_GUID, TCPIP_SEND_V6);
        assert!(!network_event(event(&send_v4, &v4_dump())).loopback);
        assert!(!network_event(event(&send_v6, &v6_dump())).loopback);

        let mut v4 = v4_dump();
        v4[8..12].copy_from_slice(&[127, 0, 0, 1]);
        v4[12..16].copy_from_slice(&[127, 0, 0, 1]);
        assert!(network_event(event(&send_v4, &v4)).loopback);

        let mut mapped = v6_dump();
        mapped[20..24].copy_from_slice(&[127, 0, 0, 1]);
        assert!(network_event(event(&send_v6, &mapped)).loopback, "v4-mapped 127.0.0.1");

        let mut v6 = v6_dump();
        v6[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        assert!(network_event(event(&send_v6, &v6)).loopback, "::1");
    }

    #[test]
    fn unknown_opcode_is_none() {
        assert!(event(&record(TCPIP_TASK_GUID, 99), &v4_dump()).is_none());
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn network_events_flow_end_to_end() {
        use std::time::{Duration, Instant};

        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (sink, rx) = crate::sink::Sink::bounded(1024, || {});
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
