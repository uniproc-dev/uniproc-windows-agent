//! Per-tick counters: which ones a subscriber wants, and the columns that carry them.

use std::sync::Arc;
use std::time::Duration;

use enumset::{EnumSet, EnumSetType};
use parking_lot::Mutex;
use smol_str::SmolStr;

use crate::snapshot::Row;

/// A row with no data in a `u32` column that has data.
pub const NO_DATA_U32: u32 = u32::MAX;
/// A row with no data in a `u64` column that has data.
pub const NO_DATA_U64: u64 = u64::MAX;

/// The shortest interval the agent samples at.
pub const MIN_INTERVAL: Duration = Duration::from_millis(100);
/// The longest; a subscriber asking for more is answered this often.
pub const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// One process counter. Everything cumulative is raw, as the OS keeps it.
#[derive(EnumSetType, Debug, Hash, PartialOrd, Ord)]
pub enum ProcessMetric {
    CpuUserTime,
    CpuKernelTime,
    CpuCycles,
    WorkingSet,
    PeakWorkingSet,
    PrivateWorkingSet,
    Commit,
    PagedPool,
    NonPagedPool,
    PageFaults,
    Handles,
    Threads,
    UserObjects,
    GdiObjects,
    IoReadOps,
    IoWriteOps,
    IoOtherOps,
    IoReadBytes,
    IoWriteBytes,
    IoOtherBytes,
    DiskReadOps,
    DiskWriteOps,
    DiskFlushOps,
    DiskReadBytes,
    DiskWriteBytes,
    NetRxBytes,
    NetTxBytes,
    VirtualSize,
    PeakVirtualSize,
    PeakCommit,
    PeakPagedPool,
    PeakNonPagedPool,
    HardFaults,
    PeakThreads,
    ContextSwitches,
    GpuDedicated,
    GpuShared,
    /// Not a column: [`Sample::gpu_engines`].
    GpuEngines,
}

/// A group of machine counters.
#[derive(EnumSetType, Debug, Hash, PartialOrd, Ord)]
pub enum MachineMetric {
    Cpu,
    Memory,
    Disk,
    Network,
    Processors,
    Gpu,
    NetworkAdapters,
}

/// A set of process counters, iterated in declaration order.
pub type ProcessMetrics = EnumSet<ProcessMetric>;

/// A set of machine groups, iterated in declaration order.
pub type MachineMetrics = EnumSet<MachineMetric>;

impl ProcessMetric {
    /// Whether a row of this column can hold [`NO_DATA_U32`] or
    /// [`NO_DATA_U64`]; page and hard faults wrap, so their maximum is a value.
    pub fn has_gaps(self) -> bool {
        !matches!(self, Self::PageFaults | Self::HardFaults)
    }
}

/// What one subscriber wants, and how often.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricSpec {
    pub interval: Duration,
    pub processes: ProcessMetrics,
    pub machine: MachineMetrics,
}

impl MetricSpec {
    /// No counters: only the processes' passports and states, this often.
    pub fn idle(interval: Duration) -> Self {
        Self {
            interval,
            processes: ProcessMetrics::empty(),
            machine: MachineMetrics::empty(),
        }
    }

    /// The interval clamped to what the agent samples at.
    pub fn period(&self) -> Duration {
        self.interval.clamp(MIN_INTERVAL, MAX_INTERVAL)
    }

    /// Everything either wants, at the shorter interval.
    pub fn union(self, other: Self) -> Self {
        Self {
            interval: self.period().min(other.period()),
            processes: self.processes.union(other.processes),
            machine: self.machine.union(other.machine),
        }
    }

    /// Everything `other` wants is in here.
    pub fn covers(&self, other: &Self) -> bool {
        self.processes.is_superset(other.processes) && self.machine.is_superset(other.machine)
    }

    /// Whether sampling for it reads the process list: it asks for a process
    /// counter, or for nothing but the lists. A spec with machine groups
    /// alone does not.
    pub fn reads_processes(&self) -> bool {
        !self.processes.is_empty() || self.machine.is_empty()
    }
}

impl Default for MetricSpec {
    fn default() -> Self {
        Self::idle(MAX_INTERVAL)
    }
}

/// What the core samples now: every spec at its own interval. Whoever keeps
/// the subscribers sets it; the core reads it at every tick.
#[derive(Clone)]
pub struct Demand(Arc<Mutex<Arc<[MetricSpec]>>>);

impl Demand {
    pub fn new(specs: impl Into<Arc<[MetricSpec]>>) -> Self {
        Self(Arc::new(Mutex::new(specs.into())))
    }

    pub fn set(&self, specs: impl Into<Arc<[MetricSpec]>>) {
        *self.0.lock() = specs.into();
    }

    pub fn get(&self) -> Arc<[MetricSpec]> {
        self.0.lock().clone()
    }
}

/// What the core knows of a listed process beside its snapshot row; asked
/// only for the columns that are wanted.
pub trait Extras {
    fn user_objects(&self, row: &Row) -> u32;
    fn gdi_objects(&self, row: &Row) -> u32;
    fn net_rx_bytes(&self, row: &Row) -> u64;
    fn net_tx_bytes(&self, row: &Row) -> u64;
    fn gpu_dedicated(&self, row: &Row) -> u64;
    fn gpu_shared(&self, row: &Row) -> u64;
}

macro_rules! columns {
    (|$r:ident, $x:ident| $($field:ident: $ty:ty = $metric:ident, $value:expr;)*) => {
        /// Process counters as columns, row i of each for the same process. A
        /// column is `None` when nobody asked for it or there is no data; a
        /// row with no data holds the type's maximum, see
        /// [`ProcessMetric::has_gaps`].
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct Columns {
            $(pub $field: Option<Arc<[$ty]>>,)*
        }

        impl Columns {
            /// The wanted columns out of `rows`, in their order.
            pub fn build(wanted: ProcessMetrics, rows: &[Row], extras: &impl Extras) -> Self {
                let $x = extras;
                Self {
                    $($field: wanted
                        .contains(ProcessMetric::$metric)
                        .then(|| rows.iter().map(|$r| $value as $ty).collect()),)*
                }
            }

            /// Only the wanted columns; the rest are `None`.
            pub fn project(&self, wanted: ProcessMetrics) -> Self {
                Self {
                    $($field: if wanted.contains(ProcessMetric::$metric) {
                        self.$field.clone()
                    } else {
                        None
                    },)*
                }
            }

            /// For a reader that takes every value as data: a column with a
            /// row that has none becomes `None`.
            pub fn without_gaps(&self) -> Self {
                Self {
                    $($field: self.$field.clone().filter(|values| {
                        !ProcessMetric::$metric.has_gaps() || !values.contains(&<$ty>::MAX)
                    }),)*
                }
            }
        }
    };
}

columns! {
    |r, x|
    cpu_user_time: u64 = CpuUserTime, r.user_time;
    cpu_kernel_time: u64 = CpuKernelTime, r.kernel_time;
    cpu_cycles: u64 = CpuCycles, r.cycles;
    working_set: u64 = WorkingSet, r.working_set;
    peak_working_set: u64 = PeakWorkingSet, r.peak_working_set;
    private_working_set: u64 = PrivateWorkingSet, r.private_working_set;
    commit: u64 = Commit, r.commit;
    paged_pool: u64 = PagedPool, r.paged_pool;
    non_paged_pool: u64 = NonPagedPool, r.nonpaged_pool;
    page_faults: u32 = PageFaults, r.page_faults;
    handles: u32 = Handles, r.handles;
    threads: u32 = Threads, r.threads;
    user_objects: u32 = UserObjects, x.user_objects(r);
    gdi_objects: u32 = GdiObjects, x.gdi_objects(r);
    io_read_ops: u64 = IoReadOps, r.io_read_ops;
    io_write_ops: u64 = IoWriteOps, r.io_write_ops;
    io_other_ops: u64 = IoOtherOps, r.io_other_ops;
    io_read_bytes: u64 = IoReadBytes, r.io_read_bytes;
    io_write_bytes: u64 = IoWriteBytes, r.io_write_bytes;
    io_other_bytes: u64 = IoOtherBytes, r.io_other_bytes;
    disk_read_ops: u64 = DiskReadOps, r.disk_read_ops;
    disk_write_ops: u64 = DiskWriteOps, r.disk_write_ops;
    disk_flush_ops: u64 = DiskFlushOps, r.disk_flush_ops;
    disk_read_bytes: u64 = DiskReadBytes, r.disk_read_bytes;
    disk_write_bytes: u64 = DiskWriteBytes, r.disk_write_bytes;
    net_rx_bytes: u64 = NetRxBytes, x.net_rx_bytes(r);
    net_tx_bytes: u64 = NetTxBytes, x.net_tx_bytes(r);
    virtual_size: u64 = VirtualSize, r.virtual_size;
    peak_virtual_size: u64 = PeakVirtualSize, r.peak_virtual_size;
    peak_commit: u64 = PeakCommit, r.peak_commit;
    peak_paged_pool: u64 = PeakPagedPool, r.peak_paged_pool;
    peak_non_paged_pool: u64 = PeakNonPagedPool, r.peak_nonpaged_pool;
    hard_faults: u32 = HardFaults, r.hard_faults;
    peak_threads: u32 = PeakThreads, r.peak_threads;
    context_switches: u64 = ContextSwitches, r.context_switches;
    gpu_dedicated: u64 = GpuDedicated, x.gpu_dedicated(r);
    gpu_shared: u64 = GpuShared, x.gpu_shared(r);
}

/// Sums over every logical processor in every group, cumulative, 100 ns.
/// Kernel time includes idle time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineCpu {
    pub idle_time: u64,
    pub kernel_time: u64,
    pub user_time: u64,
    pub interrupt_time: u64,
    pub dpc_time: u64,
    pub max_mhz: u32,
    pub current_mhz: u32,
}

/// One logical processor's times, cumulative, 100 ns. Kernel time includes
/// idle time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineProcessor {
    pub idle_time: u64,
    pub kernel_time: u64,
    pub user_time: u64,
    pub interrupt_time: u64,
    pub dpc_time: u64,
}

/// Bytes, current. The commit limit is RAM plus the page files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineMemory {
    pub total_physical: u64,
    pub available_physical: u64,
    pub commit_limit: u64,
    pub committed: u64,
}

/// All physical disks together, cumulative since the agent started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineDisk {
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// The TCP and UDP payload of every process together, cumulative since the
/// agent started. Traffic to or from a loopback address is left out; traffic
/// a process sends to the machine's own non-loopback address is not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineNetwork {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// One network adapter that is up.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct NetworkAdapter {
    /// `NET_LUID`.
    pub luid: u64,
    /// The connection's name ("Ethernet", "Wi-Fi").
    pub name: SmolStr,
    /// The driver's name for the device.
    pub description: SmolStr,
    /// IANA ifType: 6 Ethernet, 71 Wi-Fi, 53 a vendor's virtual one.
    pub if_type: u32,
    /// A physical adapter, not a virtual switch, host-only adapter or VPN.
    pub hardware: bool,
    /// Bits per second.
    pub receive_link_speed: u64,
    pub transmit_link_speed: u64,
    /// Bytes, cumulative, every protocol and header included.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// What a GPU engine does, as the driver declares it (`DXGK_ENGINE_TYPE`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub enum GpuEngineKind {
    #[default]
    Other,
    ThreeD,
    VideoDecode,
    VideoEncode,
    VideoProcessing,
    SceneAssembly,
    Copy,
    Overlay,
    Crypto,
    VideoCodec,
}

/// One engine (node) of an adapter.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct GpuEngine {
    pub ordinal: u32,
    pub kind: GpuEngineKind,
    /// The driver's name for it, often empty.
    pub name: SmolStr,
    /// Cumulative, 100 ns, all processes together; wraps.
    pub running_time: u64,
    /// Hz; 0 when the driver does not report it.
    pub frequency: u64,
    pub max_frequency: u64,
}

/// One hardware adapter.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct GpuAdapter {
    /// `HighPart << 32 | LowPart`.
    pub luid: u64,
    pub name: SmolStr,
    /// Bytes: the adapter's own memory, and system memory it maps.
    pub dedicated_limit: u64,
    pub dedicated_usage: u64,
    pub shared_limit: u64,
    pub shared_usage: u64,
    /// Tenths of a degree Celsius; 0 when the driver does not report it.
    pub temperature: u32,
    pub fan_rpm: u32,
    /// Tenths of a percent of the adapter's maximum power.
    pub power: u32,
    /// Hz.
    pub memory_frequency: u64,
    pub engines: Arc<[GpuEngine]>,
}

/// How long one process has run on one engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ProcessGpuEngine {
    /// Index into the sample's rows.
    pub row: u32,
    pub adapter_luid: u64,
    /// [`GpuEngine::ordinal`].
    pub engine: u32,
    /// Cumulative, 100 ns; wraps.
    pub running_time: u64,
}

/// A group is `None` when nobody asked for it or it could not be read.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineSample {
    pub cpu: Option<MachineCpu>,
    pub memory: Option<MachineMemory>,
    pub disk: Option<MachineDisk>,
    pub network: Option<MachineNetwork>,
    /// Group 0 first, in processor order within a group; they sum to the
    /// times in `cpu`.
    pub processors: Option<Arc<[MachineProcessor]>>,
    /// Hardware adapters only.
    pub gpus: Option<Arc<[GpuAdapter]>>,
    pub network_adapters: Option<Arc<[NetworkAdapter]>>,
}

impl MachineSample {
    pub fn project(&self, wanted: MachineMetrics) -> Self {
        Self {
            cpu: self.cpu.filter(|_| wanted.contains(MachineMetric::Cpu)),
            memory: self.memory.filter(|_| wanted.contains(MachineMetric::Memory)),
            disk: self.disk.filter(|_| wanted.contains(MachineMetric::Disk)),
            network: self.network.filter(|_| wanted.contains(MachineMetric::Network)),
            processors: self.processors.clone().filter(|_| wanted.contains(MachineMetric::Processors)),
            gpus: self.gpus.clone().filter(|_| wanted.contains(MachineMetric::Gpu)),
            network_adapters: self
                .network_adapters
                .clone()
                .filter(|_| wanted.contains(MachineMetric::NetworkAdapters)),
        }
    }
}

/// Everything sampled at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// Moves with every sample the agent takes.
    pub snapshot: u64,
    /// QueryPerformanceCounter in 100 ns units; only differences mean anything.
    pub sampled_at: u64,
    /// How often the agent was sampling when it took this one; over the pipe,
    /// the subscription's own interval.
    pub period: Duration,
    /// What the sample was taken for; a subscriber it covers can use it.
    pub wanted: MetricSpec,
    /// The tag of the process list the rows are exactly; set by whoever joins
    /// the sample with that list, 0 until then.
    pub passport_etag: u64,
    pub pids: Arc<[u32]>,
    /// The join key: never reused within a boot, 0 only for the Idle process.
    pub sequence_numbers: Arc<[u64]>,
    pub columns: Columns,
    /// Sparse: a process and an engine it has run on per entry.
    pub gpu_engines: Option<Arc<[ProcessGpuEngine]>>,
    pub machine: MachineSample,
}

impl Sample {
    /// Only what `spec` asks for; no rows when it asks for no process metric.
    pub fn project(&self, spec: &MetricSpec) -> Self {
        let rows = !spec.processes.is_empty();
        Self {
            wanted: *spec,
            pids: if rows { self.pids.clone() } else { Arc::from([]) },
            sequence_numbers: if rows {
                self.sequence_numbers.clone()
            } else {
                Arc::from([])
            },
            columns: self.columns.project(spec.processes),
            gpu_engines: self
                .gpu_engines
                .clone()
                .filter(|_| spec.processes.contains(ProcessMetric::GpuEngines)),
            machine: self.machine.project(spec.machine),
            ..*self
        }
    }
}

/// QueryPerformanceCounter now, in 100 ns units.
pub fn now_100ns() -> u64 {
    let (mut count, mut frequency) = (0i64, 0i64);
    unsafe {
        let _ = windows::Win32::QueryPerformanceCounter(&mut count);
        let _ = windows::Win32::QueryPerformanceFrequency(&mut frequency);
    }
    if frequency <= 0 {
        return 0;
    }
    (count as u128 * 10_000_000 / frequency as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_without_gaps_loses_only_the_columns_that_have_them() {
        let columns = Columns {
            gdi_objects: Some(Arc::from([12, NO_DATA_U32])),
            handles: Some(Arc::from([1, 2])),
            page_faults: Some(Arc::from([u32::MAX, 3])),
            working_set: Some(Arc::from([NO_DATA_U64, 5])),
            ..Default::default()
        };
        let plain = columns.without_gaps();
        assert_eq!(plain.gdi_objects, None);
        assert_eq!(plain.working_set, None);
        assert_eq!(plain.handles, columns.handles);
        assert_eq!(plain.page_faults, columns.page_faults, "a wrapped count is a value");
    }

    fn row(pid: u32, working_set: u64) -> Row {
        Row {
            pid,
            working_set,
            user_time: pid as u64 * 10,
            ..Default::default()
        }
    }

    #[derive(Default)]
    struct Asked(std::cell::Cell<u32>);

    impl Extras for Asked {
        fn user_objects(&self, _: &Row) -> u32 {
            self.0.set(self.0.get() + 1);
            3
        }
        fn gdi_objects(&self, _: &Row) -> u32 {
            self.0.set(self.0.get() + 1);
            4
        }
        fn net_rx_bytes(&self, row: &Row) -> u64 {
            self.0.set(self.0.get() + 1);
            row.pid as u64 * 7
        }
        fn net_tx_bytes(&self, _: &Row) -> u64 {
            self.0.set(self.0.get() + 1);
            0
        }
        fn gpu_dedicated(&self, _: &Row) -> u64 {
            self.0.set(self.0.get() + 1);
            0
        }
        fn gpu_shared(&self, _: &Row) -> u64 {
            self.0.set(self.0.get() + 1);
            0
        }
    }

    #[test]
    fn only_wanted_columns_are_built_and_only_their_extras_asked() {
        let wanted: ProcessMetrics = [ProcessMetric::WorkingSet, ProcessMetric::NetRxBytes].into_iter().collect();
        let asked = Asked::default();
        let columns = Columns::build(wanted, &[row(1, 100), row(2, 200)], &asked);
        assert_eq!(columns.working_set.as_deref(), Some(&[100, 200][..]));
        assert_eq!(columns.net_rx_bytes.as_deref(), Some(&[7, 14][..]));
        assert_eq!(columns.cpu_user_time, None);
        assert_eq!(asked.0.get(), 2, "one question per row of the one wanted extra");
    }

    #[test]
    fn a_projection_shares_the_columns_it_keeps() {
        let columns = Columns::build(ProcessMetrics::all(), &[row(1, 100)], &Asked::default());
        let only: ProcessMetrics = [ProcessMetric::CpuUserTime].into_iter().collect();
        let projected = columns.project(only);
        assert!(Arc::ptr_eq(
            projected.cpu_user_time.as_ref().unwrap(),
            columns.cpu_user_time.as_ref().unwrap()
        ));
        assert_eq!(projected.working_set, None);
    }

    #[test]
    fn a_union_samples_at_the_shorter_interval() {
        let a = MetricSpec {
            interval: Duration::from_secs(2),
            processes: [ProcessMetric::Handles].into_iter().collect(),
            machine: MachineMetrics::empty(),
        };
        let b = MetricSpec {
            interval: Duration::from_millis(500),
            processes: ProcessMetrics::empty(),
            machine: [MachineMetric::Cpu].into_iter().collect(),
        };
        let both = a.union(b);
        assert_eq!(both.interval, Duration::from_millis(500));
        assert!(both.processes.contains(ProcessMetric::Handles));
        assert!(both.machine.contains(MachineMetric::Cpu));
    }

    #[test]
    fn an_interval_out_of_range_is_clamped() {
        let spec = |ms| MetricSpec::idle(Duration::from_millis(ms));
        assert_eq!(spec(0).period(), MIN_INTERVAL);
        assert_eq!(spec(3_600_000).period(), MAX_INTERVAL);
    }

    #[test]
    fn a_spec_covers_the_metrics_it_has_whatever_the_interval() {
        let wide = MetricSpec {
            interval: Duration::from_secs(2),
            processes: ProcessMetrics::all(),
            machine: MachineMetric::Cpu.into(),
        };
        let narrow = MetricSpec {
            interval: Duration::from_millis(250),
            processes: ProcessMetric::Handles.into(),
            machine: MachineMetrics::empty(),
        };
        assert!(wide.covers(&narrow));
        assert!(!narrow.covers(&wide));
        assert!(narrow.covers(&MetricSpec::idle(Duration::from_secs(1))));
    }

    #[test]
    fn the_clock_moves_forward() {
        let first = now_100ns();
        std::thread::sleep(Duration::from_millis(5));
        assert!(now_100ns() > first);
    }
}
