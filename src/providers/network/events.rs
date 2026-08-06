use binrw::BinRead;

/// Common prefix of TcpIp/UdpIp IPv4 events (opcodes 10/11/12/15 on the
/// respective provider). Layouts: `TcpIp_SendIPV4`, `TcpIp_TypeGroup1`,
/// `TcpIp_TypeGroup2`, `UdpIp_TypeGroup1`. The tail (timestamps, seqnum,
/// connid, ...) is unused and left unparsed.
///
/// ```c++
/// class TcpIp_TypeGroup1 : TcpIp
/// {
///     [WmiDataId(1), read] uint32 PID;
///     [WmiDataId(2), read] uint32 size;
///     [WmiDataId(3), extension("IPAddr"), read] object daddr;  // 4 bytes
///     [WmiDataId(4), extension("IPAddr"), read] object saddr;  // 4 bytes
///     [WmiDataId(5), extension("Port"), read] object dport;
///     [WmiDataId(6), extension("Port"), read] object sport;
///     // ...
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
pub struct Ipv4Flow {
    pub pid: u32,
    pub size: u32,
    pub dst_addr: [u8; 4],
    pub src_addr: [u8; 4],
    pub dst_port_be: u16,
    pub src_port_be: u16,
}

/// Common prefix of TcpIp/UdpIp IPv6 events (opcodes 26/27/28/31 on the
/// respective provider). Layouts: `TcpIp_SendIPV6`, `TcpIp_TypeGroup3`,
/// `TcpIp_TypeGroup4`, `UdpIp_TypeGroup2`. The tail (mss, windows, seqnum,
/// connid, ...) is unused and left unparsed.
#[derive(BinRead, Debug)]
#[br(little)]
pub struct Ipv6Flow {
    pub pid: u32,
    pub size: u32,
    pub dst_addr: [u8; 16],
    pub src_addr: [u8; 16],
    pub dst_port_be: u16,
    pub src_port_be: u16,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::etw::signatures::utils::{parse, to_ip4};
    use std::net::{IpAddr, Ipv4Addr};

    /// Full-length `TcpIp_SendIPV4` payload (36 bytes as observed on Win11);
    /// only the prefix is parsed. pid=1234, size=1460,
    /// src=192.168.0.1:8080, dst=192.168.0.2:443.
    pub fn v4_dump() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1234u32.to_le_bytes());
        v.extend_from_slice(&1460u32.to_le_bytes());
        v.extend_from_slice(&[192, 168, 0, 2]); // dst_addr
        v.extend_from_slice(&[192, 168, 0, 1]); // src_addr
        v.extend_from_slice(&443u16.to_be_bytes()); // dst_port, wire order
        v.extend_from_slice(&8080u16.to_be_bytes()); // src_port
        v.extend_from_slice(&[0u8; 16]); // startime, endtime, seqnum, connid
        v
    }

    /// Full-length `UdpIp_TypeGroup2` payload (52 bytes as observed on Win11).
    /// src=10.0.0.1:8080, dst=10.0.0.2:53 (v4-mapped in 16-byte fields).
    pub fn v6_dump() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&4321u32.to_le_bytes());
        v.extend_from_slice(&40u32.to_le_bytes());
        v.extend_from_slice(&[0u8; 10]);
        v.extend_from_slice(&[0xff, 0xff, 10, 0, 0, 2]); // dst_addr
        v.extend_from_slice(&[0u8; 10]);
        v.extend_from_slice(&[0xff, 0xff, 10, 0, 0, 1]); // src_addr
        v.extend_from_slice(&53u16.to_be_bytes());
        v.extend_from_slice(&8080u16.to_be_bytes());
        v.extend_from_slice(&[0u8; 8]); // seqnum, connid
        v
    }

    #[test]
    fn parses_ipv4_flow() {
        let f = parse::<Ipv4Flow>(&v4_dump()).expect("valid dump");
        assert_eq!(f.pid, 1234);
        assert_eq!(f.size, 1460);
        assert_eq!(IpAddr::from(f.src_addr), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(u16::from_be(f.src_port_be), 8080);
        assert_eq!(u16::from_be(f.dst_port_be), 443);
    }

    #[test]
    fn parses_ipv6_flow() {
        let f = parse::<Ipv6Flow>(&v6_dump()).expect("valid dump");
        assert_eq!(f.pid, 4321);
        assert_eq!(f.size, 40);
        assert_eq!(to_ip4(f.src_addr), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(to_ip4(f.dst_addr), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(u16::from_be(f.dst_port_be), 53);
    }

    #[test]
    fn truncated_dump_is_none() {
        assert!(parse::<Ipv4Flow>(&v4_dump()[..10]).is_none());
        assert!(parse::<Ipv6Flow>(&v6_dump()[..30]).is_none());
    }
}
