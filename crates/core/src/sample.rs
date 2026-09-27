//! Per-tick counters: which ones a subscriber wants, and the columns that carry them.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::snapshot::Row;

/// One process counter. Everything cumulative is raw, as the OS keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
}

impl ProcessMetric {
    pub const ALL: [Self; 27] = [
        Self::CpuUserTime,
        Self::CpuKernelTime,
        Self::CpuCycles,
        Self::WorkingSet,
        Self::PeakWorkingSet,
        Self::PrivateWorkingSet,
        Self::Commit,
        Self::PagedPool,
        Self::NonPagedPool,
        Self::PageFaults,
        Self::Handles,
        Self::Threads,
        Self::UserObjects,
        Self::GdiObjects,
        Self::IoReadOps,
        Self::IoWriteOps,
        Self::IoOtherOps,
        Self::IoReadBytes,
        Self::IoWriteBytes,
        Self::IoOtherBytes,
        Self::DiskReadOps,
        Self::DiskWriteOps,
        Self::DiskFlushOps,
        Self::DiskReadBytes,
        Self::DiskWriteBytes,
        Self::NetRxBytes,
        Self::NetTxBytes,
    ];

    /// Whether a row of this column can hold [`NO_DATA_U32`] or
    /// [`NO_DATA_U64`]; page faults wrap, so their maximum is a value.
    pub fn has_gaps(self) -> bool {
        self != Self::PageFaults
    }

    fn bit(self) -> u32 {
        1 << self as u32
    }
}

/// A row with no data in a `u32` column that has data.
pub const NO_DATA_U32: u32 = u32::MAX;
/// A row with no data in a `u64` column that has data.
pub const NO_DATA_U64: u64 = u64::MAX;

/// A set of process counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProcessMetrics(u32);

impl ProcessMetrics {
    pub const NONE: Self = Self(0);

    pub fn all() -> Self {
        ProcessMetric::ALL.into_iter().collect()
    }

    pub fn contains(self, metric: ProcessMetric) -> bool {
        self.0 & metric.bit() != 0
    }

    pub fn insert(&mut self, metric: ProcessMetric) {
        self.0 |= metric.bit();
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Every metric of `other` is in this set.
    pub fn covers(self, other: Self) -> bool {
        other.0 & !self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = ProcessMetric> {
        ProcessMetric::ALL.into_iter().filter(move |&m| self.contains(m))
    }
}

impl FromIterator<ProcessMetric> for ProcessMetrics {
    fn from_iter<I: IntoIterator<Item = ProcessMetric>>(iter: I) -> Self {
        let mut set = Self::NONE;
        for metric in iter {
            set.insert(metric);
        }
        set
    }
}

/// A group of machine counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MachineMetric {
    Cpu,
    Memory,
    Disk,
    Network,
}

impl MachineMetric {
    pub const ALL: [Self; 4] = [Self::Cpu, Self::Memory, Self::Disk, Self::Network];
}

/// A set of machine groups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MachineMetrics(u8);

impl MachineMetrics {
    pub const NONE: Self = Self(0);

    pub fn all() -> Self {
        MachineMetric::ALL.into_iter().collect()
    }

    pub fn contains(self, metric: MachineMetric) -> bool {
        self.0 & (1 << metric as u8) != 0
    }

    pub fn insert(&mut self, metric: MachineMetric) {
        self.0 |= 1 << metric as u8;
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Every group of `other` is in this set.
    pub fn covers(self, other: Self) -> bool {
        other.0 & !self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = MachineMetric> {
        MachineMetric::ALL.into_iter().filter(move |&m| self.contains(m))
    }
}

impl FromIterator<MachineMetric> for MachineMetrics {
    fn from_iter<I: IntoIterator<Item = MachineMetric>>(iter: I) -> Self {
        let mut set = Self::NONE;
        for metric in iter {
            set.insert(metric);
        }
        set
    }
}

/// What one subscriber wants, and how often.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricSpec {
    pub interval: Duration,
    pub processes: ProcessMetrics,
    pub machine: MachineMetrics,
}

/// The shortest interval the agent samples at.
pub const MIN_INTERVAL: Duration = Duration::from_millis(100);

/// The longest; a subscriber asking for more is answered this often.
pub const MAX_INTERVAL: Duration = Duration::from_secs(60);

impl MetricSpec {
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
        self.processes.covers(other.processes) && self.machine.covers(other.machine)
    }
}

/// What the live subscribers want together, and how often the core samples
/// while none does. Shared between whoever keeps the subscribers and the core.
#[derive(Clone)]
pub struct Demand {
    state: Arc<Mutex<DemandState>>,
}

#[derive(Clone, Copy)]
struct DemandState {
    wanted: Option<MetricSpec>,
    idle: Duration,
    grown: bool,
}

impl Demand {
    pub fn new(idle: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(DemandState {
                wanted: None,
                idle,
                grown: false,
            })),
        }
    }

    /// The union of the live subscriptions; `None` when there are none.
    pub fn set_wanted(&self, wanted: Option<MetricSpec>) {
        let mut state = self.state.lock();
        let held = state.wanted.unwrap_or(MetricSpec {
            interval: state.idle,
            processes: ProcessMetrics::NONE,
            machine: MachineMetrics::NONE,
        });
        if wanted.is_some_and(|w| !held.covers(&w) || w.period() < held.period()) {
            state.grown = true;
        }
        state.wanted = wanted;
    }

    /// Whether someone started wanting more since the last call: the next
    /// sample is due at once instead of at the end of the period.
    pub fn take_grown(&self) -> bool {
        std::mem::take(&mut self.state.lock().grown)
    }

    pub fn set_idle(&self, idle: Duration) {
        self.state.lock().idle = idle;
    }

    /// What to sample now: the subscriptions' union, or nothing but the
    /// processes' passports and states at the idle period.
    pub fn now(&self) -> MetricSpec {
        let state = *self.state.lock();
        state.wanted.unwrap_or(MetricSpec {
            interval: state.idle,
            processes: ProcessMetrics::NONE,
            machine: MachineMetrics::NONE,
        })
    }

    /// How often the core should sample.
    pub fn period(&self) -> Duration {
        self.now().period()
    }
}

/// What one process's row is built from.
#[derive(Clone, Copy, Debug, Default)]
pub struct Source {
    pub row: Row,
    pub user_objects: u32,
    pub gdi_objects: u32,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

macro_rules! columns {
    ($($field:ident: $ty:ty = $metric:ident, |$s:ident| $value:expr;)*) => {
        /// Process counters as columns, row i of each for the same process. A
        /// column is `None` when nobody asked for it or there is no data; a
        /// row with no data holds the type's maximum, see
        /// [`ProcessMetric::has_gaps`].
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct Columns {
            $(pub $field: Option<Arc<[$ty]>>,)*
        }

        impl Columns {
            /// The wanted columns out of `sources`, in their order.
            pub fn build(wanted: ProcessMetrics, sources: &[Source]) -> Self {
                Self {
                    $($field: wanted
                        .contains(ProcessMetric::$metric)
                        .then(|| sources.iter().map(|$s| $value as $ty).collect()),)*
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
    cpu_user_time: u64 = CpuUserTime, |s| s.row.user_time;
    cpu_kernel_time: u64 = CpuKernelTime, |s| s.row.kernel_time;
    cpu_cycles: u64 = CpuCycles, |s| s.row.cycles;
    working_set: u64 = WorkingSet, |s| s.row.working_set;
    peak_working_set: u64 = PeakWorkingSet, |s| s.row.peak_working_set;
    private_working_set: u64 = PrivateWorkingSet, |s| s.row.private_working_set;
    commit: u64 = Commit, |s| s.row.commit;
    paged_pool: u64 = PagedPool, |s| s.row.paged_pool;
    non_paged_pool: u64 = NonPagedPool, |s| s.row.nonpaged_pool;
    page_faults: u32 = PageFaults, |s| s.row.page_faults;
    handles: u32 = Handles, |s| s.row.handles;
    threads: u32 = Threads, |s| s.row.threads;
    user_objects: u32 = UserObjects, |s| s.user_objects;
    gdi_objects: u32 = GdiObjects, |s| s.gdi_objects;
    io_read_ops: u64 = IoReadOps, |s| s.row.io_read_ops;
    io_write_ops: u64 = IoWriteOps, |s| s.row.io_write_ops;
    io_other_ops: u64 = IoOtherOps, |s| s.row.io_other_ops;
    io_read_bytes: u64 = IoReadBytes, |s| s.row.io_read_bytes;
    io_write_bytes: u64 = IoWriteBytes, |s| s.row.io_write_bytes;
    io_other_bytes: u64 = IoOtherBytes, |s| s.row.io_other_bytes;
    disk_read_ops: u64 = DiskReadOps, |s| s.row.disk_read_ops;
    disk_write_ops: u64 = DiskWriteOps, |s| s.row.disk_write_ops;
    disk_flush_ops: u64 = DiskFlushOps, |s| s.row.disk_flush_ops;
    disk_read_bytes: u64 = DiskReadBytes, |s| s.row.disk_read_bytes;
    disk_write_bytes: u64 = DiskWriteBytes, |s| s.row.disk_write_bytes;
    net_rx_bytes: u64 = NetRxBytes, |s| s.net_rx_bytes;
    net_tx_bytes: u64 = NetTxBytes, |s| s.net_tx_bytes;
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

/// Bytes, current.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineMemory {
    pub total_physical: u64,
    pub available_physical: u64,
}

/// All physical disks together, cumulative since the agent started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineDisk {
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// All network adapters together, cumulative since the agent started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineNetwork {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// A group is `None` when nobody asked for it or it could not be read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineSample {
    pub cpu: Option<MachineCpu>,
    pub memory: Option<MachineMemory>,
    pub disk: Option<MachineDisk>,
    pub network: Option<MachineNetwork>,
}

impl MachineSample {
    pub fn project(&self, wanted: MachineMetrics) -> Self {
        Self {
            cpu: self.cpu.filter(|_| wanted.contains(MachineMetric::Cpu)),
            memory: self.memory.filter(|_| wanted.contains(MachineMetric::Memory)),
            disk: self.disk.filter(|_| wanted.contains(MachineMetric::Disk)),
            network: self.network.filter(|_| wanted.contains(MachineMetric::Network)),
        }
    }
}

impl Default for MetricSpec {
    fn default() -> Self {
        Self {
            interval: MAX_INTERVAL,
            processes: ProcessMetrics::NONE,
            machine: MachineMetrics::NONE,
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

    fn source(pid: u32, working_set: u64) -> Source {
        Source {
            row: Row {
                pid,
                working_set,
                user_time: pid as u64 * 10,
                ..Default::default()
            },
            net_rx_bytes: 7,
            ..Default::default()
        }
    }

    #[test]
    fn only_wanted_columns_are_built() {
        let wanted: ProcessMetrics = [ProcessMetric::WorkingSet, ProcessMetric::NetRxBytes].into_iter().collect();
        let columns = Columns::build(wanted, &[source(1, 100), source(2, 200)]);
        assert_eq!(columns.working_set.as_deref(), Some(&[100, 200][..]));
        assert_eq!(columns.net_rx_bytes.as_deref(), Some(&[7, 7][..]));
        assert_eq!(columns.cpu_user_time, None);
    }

    #[test]
    fn a_projection_shares_the_columns_it_keeps() {
        let columns = Columns::build(ProcessMetrics::all(), &[source(1, 100)]);
        let only: ProcessMetrics = [ProcessMetric::CpuUserTime].into_iter().collect();
        let projected = columns.project(only);
        assert!(Arc::ptr_eq(
            projected.cpu_user_time.as_ref().unwrap(),
            columns.cpu_user_time.as_ref().unwrap()
        ));
        assert_eq!(projected.working_set, None);
    }

    #[test]
    fn every_metric_has_its_own_bit() {
        let all = ProcessMetrics::all();
        assert_eq!(all.iter().count(), ProcessMetric::ALL.len());
        for metric in ProcessMetric::ALL {
            let one: ProcessMetrics = [metric].into_iter().collect();
            assert_eq!(one.iter().collect::<Vec<_>>(), [metric]);
        }
    }

    #[test]
    fn a_union_samples_at_the_shorter_interval() {
        let a = MetricSpec {
            interval: Duration::from_secs(2),
            processes: [ProcessMetric::Handles].into_iter().collect(),
            machine: MachineMetrics::NONE,
        };
        let b = MetricSpec {
            interval: Duration::from_millis(500),
            processes: ProcessMetrics::NONE,
            machine: [MachineMetric::Cpu].into_iter().collect(),
        };
        let both = a.union(b);
        assert_eq!(both.interval, Duration::from_millis(500));
        assert!(both.processes.contains(ProcessMetric::Handles));
        assert!(both.machine.contains(MachineMetric::Cpu));
    }

    #[test]
    fn an_interval_out_of_range_is_clamped() {
        let spec = |ms| MetricSpec {
            interval: Duration::from_millis(ms),
            processes: ProcessMetrics::NONE,
            machine: MachineMetrics::NONE,
        };
        assert_eq!(spec(0).period(), MIN_INTERVAL);
        assert_eq!(spec(3_600_000).period(), MAX_INTERVAL);
    }

    #[test]
    fn wanting_more_makes_the_next_sample_due_and_wanting_less_does_not() {
        let demand = Demand::new(Duration::from_secs(2));
        let wide = MetricSpec {
            interval: Duration::from_secs(1),
            processes: ProcessMetrics::all(),
            machine: MachineMetrics::NONE,
        };
        demand.set_wanted(Some(wide));
        assert!(demand.take_grown());
        assert!(!demand.take_grown(), "taken once");

        demand.set_wanted(Some(MetricSpec {
            processes: [ProcessMetric::Handles].into_iter().collect(),
            ..wide
        }));
        assert!(!demand.take_grown());
        demand.set_wanted(None);
        assert!(!demand.take_grown());
    }

    #[test]
    fn a_set_covers_its_subsets_only() {
        let both: ProcessMetrics = [ProcessMetric::Handles, ProcessMetric::Threads].into_iter().collect();
        let one: ProcessMetrics = [ProcessMetric::Handles].into_iter().collect();
        assert!(both.covers(one) && both.covers(ProcessMetrics::NONE));
        assert!(!one.covers(both));
    }

    #[test]
    fn with_nobody_subscribed_the_core_samples_at_the_idle_period() {
        let demand = Demand::new(Duration::from_secs(2));
        assert_eq!(demand.period(), Duration::from_secs(2));
        assert!(demand.now().processes.is_empty());
        demand.set_wanted(Some(MetricSpec {
            interval: Duration::from_millis(250),
            processes: ProcessMetrics::all(),
            machine: MachineMetrics::all(),
        }));
        assert_eq!(demand.period(), Duration::from_millis(250));
    }

    #[test]
    fn the_clock_moves_forward() {
        let first = now_100ns();
        std::thread::sleep(Duration::from_millis(5));
        assert!(now_100ns() > first);
    }
}
