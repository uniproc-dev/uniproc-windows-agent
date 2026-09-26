#[derive(Clone, Debug, Default)]
pub struct ProcessStarted {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub image_name: String,
    pub command_line: Vec<String>,
    pub package_full_name: String,
    pub package_relative_app_id: String,
    /// Kernel pseudo-process (Idle, System, Registry, ...): no image on disk.
    pub is_kernel_process: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProcessSignature {
    /// Not checked yet, or the check itself failed.
    #[default]
    Unknown,
    Unsigned,
    Microsoft,
    ThirdParty,
}

/// Follow-up enrichment for an already reported process: everything that
/// requires opening the process / inspecting its image file.
#[derive(Clone, Debug, Default)]
pub struct ProcessEnriched {
    pub pid: u32,
    pub command_line: Vec<String>,
    pub image_path: String,
    /// Human-facing name (FileDescription / manifest / shell). Empty when
    /// none of the sources answered - `image_name` stays the fallback.
    pub display_name: String,
    pub signature: ProcessSignature,
    pub is_windows_process: bool,
    /// Pid of the conhost serving the console at enrichment, 0 for none.
    pub console_host_pid: u32,
}

#[derive(Clone, Debug, Default)]
pub struct MemorySnapshot {
    pub pid: u32,
    pub working_set_bytes: u64,
    pub peak_working_set_bytes: u64,
    pub private_working_set_bytes: u64,
    pub private_bytes: u64,
    #[cfg_attr(not(feature = "service"), allow(dead_code))]
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MachineSnapshot {
    pub total_physical_kb: u64,
    pub available_physical_kb: u64,
    pub used_physical_kb: u64,
    pub cpu_percent: f32,
    pub cpu_interrupt_percent: f32,
    pub cpu_dpc_percent: f32,
    pub cpu_max_mhz: u64,
    pub cpu_current_mhz: u64,
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

pub type NetDeltas = fxhash::FxHashMap<u32, NetDelta>;

/// Disk transfers keyed by the thread that issued them. Cached writes are
/// issued by the lazy writer's threads and so land on System.
pub type DiskDeltas = fxhash::FxHashMap<u32, DiskDelta>;

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
    ProcessStarted(Box<ProcessStarted>),
    ProcessRundown(Box<ProcessStarted>),
    /// Enrichment resolved off the shared ETW pump thread, after the initial
    /// `ProcessStarted`/`ProcessRundown` already inserted the entry.
    ProcessEnriched(Box<ProcessEnriched>),
    ProcessStopped(u32),
    ThreadStarted { pid: u32, tid: u32 },
    ThreadStopped { tid: u32 },
    /// Whole-set snapshots from the periodic inventory; they replace the
    /// previous sets instead of diffing per process.
    ServicesSnapshot(Vec<crate::providers::utils::ServiceInfo>),
    Memory(Vec<MemorySnapshot>),
    Machine(Box<MachineSnapshot>),
    Disk(DiskDeltas),
    Network(NetDeltas),
    /// Profile samples per thread since the previous batch, attributed to
    /// processes when applied and shared out at the next machine snapshot.
    CpuSamples(crate::providers::cpu_sampler::counters::Samples),
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
