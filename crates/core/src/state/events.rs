use smol_str::SmolStr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProcessSignature {
    /// Not checked yet, or the check itself failed.
    #[default]
    Unknown,
    Unsigned,
    Microsoft,
    ThirdParty,
}

/// What an executable is, whoever runs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImageVerdict {
    pub signature: ProcessSignature,
    pub is_windows_process: bool,
    /// Human-facing name (FileDescription / manifest / shell). Empty when
    /// none of the sources answered - the image name stays the fallback.
    pub display_name: SmolStr,
    /// A package's PublisherDisplayName, otherwise the signer's subject name.
    pub publisher: SmolStr,
}

/// A verdict on one image, judged off the tick's thread.
#[derive(Clone, Debug, Default)]
pub struct Image {
    pub path: SmolStr,
    pub verdict: ImageVerdict,
}

#[derive(Clone, Debug)]
pub struct DiskEvent {
    pub event_type: DiskEventType,
    pub transfer_size: u64,
}

#[derive(Clone, Debug)]
pub enum DiskEventType {
    Read,
    Write,
}

/// Physical disk transfers across the machine since the previous batch.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DiskDelta {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}

impl DiskDelta {
    pub fn add(&mut self, e: &DiskEvent) {
        match e.event_type {
            DiskEventType::Read => {
                self.read_bytes += e.transfer_size;
                self.read_ops += 1;
            }
            DiskEventType::Write => {
                self.write_bytes += e.transfer_size;
                self.write_ops += 1;
            }
        }
    }
}

/// One process's traffic since the previous batch.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NetDelta {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl NetDelta {
    pub fn add(&mut self, e: &NetworkEvent) {
        match e.event_type {
            NetworkEventType::Send => {
                self.tx_bytes += e.size as u64;
                self.tx_packets += 1;
            }
            NetworkEventType::Recv => {
                self.rx_bytes += e.size as u64;
                self.rx_packets += 1;
            }
            _ => {}
        }
    }
}

pub type NetDeltas = rustc_hash::FxHashMap<u32, NetDelta>;

/// Disk transfers keyed by the thread that issued them. Cached writes are
/// issued by the lazy writer's threads and so land on System.
pub type DiskDeltas = rustc_hash::FxHashMap<u32, DiskDelta>;

#[derive(Clone, Debug)]
pub struct NetworkEvent {
    pub pid: u32,
    pub event_type: NetworkEventType,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub enum NetworkEventType {
    Send,
    Recv,
    Connect,
    Accept,
}

#[derive(Debug, Clone)]
pub enum StateChange {
    Disk(DiskDeltas),
    Network(NetDeltas),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_change_is_sized_by_the_frequent_events_not_the_rare_ones() {
        assert!(
            std::mem::size_of::<StateChange>() <= 40,
            "StateChange is {} bytes: box the rare large payloads, every channel slot pays for the largest",
            std::mem::size_of::<StateChange>()
        );
    }

    fn net(event_type: NetworkEventType, size: u32) -> NetworkEvent {
        NetworkEvent {
            pid: 1,
            event_type,
            size,
        }
    }

    #[test]
    fn traffic_adds_up_by_direction_and_connects_carry_none() {
        let mut d = NetDelta::default();
        d.add(&net(NetworkEventType::Send, 100));
        d.add(&net(NetworkEventType::Send, 20));
        d.add(&net(NetworkEventType::Recv, 7));
        d.add(&net(NetworkEventType::Connect, 999));
        assert_eq!(
            d,
            NetDelta {
                rx_bytes: 7,
                tx_bytes: 120,
                rx_packets: 1,
                tx_packets: 2,
            }
        );
    }

    #[test]
    fn disk_transfers_add_up_by_direction() {
        let mut d = DiskDelta::default();
        for (event_type, size) in [(DiskEventType::Read, 512), (DiskEventType::Write, 4096), (DiskEventType::Write, 4096)] {
            d.add(&DiskEvent {
                event_type,
                transfer_size: size,
            });
        }
        assert_eq!(
            d,
            DiskDelta {
                read_bytes: 512,
                write_bytes: 8192,
                read_ops: 1,
                write_ops: 2,
            }
        );
    }
}
