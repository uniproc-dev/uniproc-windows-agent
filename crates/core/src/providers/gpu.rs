//! Hardware adapters, their engines and memory, and what each process uses
//! of them, from D3DKMTQueryStatistics as Task Manager reads them.
//!
//! The kernel's own per-engine totals answer through the driver and cost a
//! millisecond or more each, so an engine's total is the sum of what the
//! processes' reads added to it, which cost a microsecond.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use smol_str::SmolStr;
use windows::Win32::{
    D3DKMT_ADAPTER_PERFDATA, D3DKMT_ADAPTERINFO, D3DKMT_ADAPTERREGISTRYINFO, D3DKMT_ADAPTERTYPE,
    D3DKMT_CLOSEADAPTER, D3DKMT_DRIVER_DESCRIPTION, D3DKMT_ENUMADAPTERS2, D3DKMT_HANDLE, D3DKMT_NODE_PERFDATA,
    D3DKMT_NODEMETADATA, D3DKMT_QUERYADAPTERINFO, D3DKMT_QUERYSTATISTICS, D3DKMT_QUERYSTATISTICS_ADAPTER,
    D3DKMT_QUERYSTATISTICS_PROCESS_NODE, D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT, D3DKMT_QUERYSTATISTICS_SEGMENT,
    D3DKMT_QUERYSTATISTICS_TYPE, D3DKMT_SEGMENTSIZEINFO, D3DKMTCloseAdapter, D3DKMTEnumAdapters2,
    D3DKMTQueryAdapterInfo, D3DKMTQueryStatistics, HANDLE, KMTQAITYPE_ADAPTERPERFDATA,
    KMTQAITYPE_ADAPTERREGISTRYINFO, KMTQAITYPE_ADAPTERTYPE, KMTQAITYPE_DRIVER_DESCRIPTION,
    KMTQAITYPE_GETSEGMENTSIZE, KMTQAITYPE_NODEMETADATA, KMTQAITYPE_NODEPERFDATA, KMTQUERYADAPTERINFOTYPE, LUID,
};

use crate::probes::{Handles, PROBE_ROUND, turn};
use crate::sample::{GpuAdapter, GpuEngine, GpuEngineKind, NO_DATA_U64, ProcessGpuEngine};
use crate::snapshot::Row;

/// How often the adapters are enumerated again, to see one come or go.
const ENUMERATE_EVERY: Duration = Duration::from_secs(60);

const SOFTWARE_DEVICE: u32 = 1 << 2;

/// What a tick asks of the GPUs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wanted {
    pub memory: bool,
    pub engines: bool,
    pub adapters: bool,
}

impl Wanted {
    pub fn any(self) -> bool {
        self.memory || self.engines || self.adapters
    }
}

/// What a tick read.
#[derive(Default)]
pub struct Read {
    pub adapters: Option<Arc<[GpuAdapter]>>,
    pub engines: Option<Arc<[ProcessGpuEngine]>>,
}

struct Node {
    ordinal: u32,
    kind: GpuEngineKind,
    name: SmolStr,
    max_frequency: u64,
    total: u64,
}

struct Segment {
    id: u32,
    aperture: bool,
}

struct Adapter {
    handle: D3DKMT_HANDLE,
    luid: LUID,
    key: u64,
    name: SmolStr,
    nodes: Vec<Node>,
    segments: Vec<Segment>,
    shared_limit: u64,
}

impl Drop for Adapter {
    fn drop(&mut self) {
        close(self.handle);
    }
}

/// What a process holds on one adapter, as last read.
struct On {
    key: u64,
    nodes: Vec<u64>,
}

struct Used {
    sequence_number: u64,
    listed: u64,
    dedicated: u64,
    shared: u64,
    on: Vec<On>,
    checked: bool,
}

/// The hardware adapters, and what each process was last seen using. A
/// process is read every tick while it has a context on an adapter or is
/// younger than [`PROBE_ROUND`], when most create one; an older one that
/// had none when last read is read again in its turn, each within
/// [`PROBE_ROUND`], and holds nothing until then.
#[derive(Default)]
pub struct Gpu {
    adapters: Vec<Adapter>,
    enumerated: Option<Instant>,
    processes: FxHashMap<u32, Used>,
    ticks: u64,
    scratch: Vec<u64>,
    cursor: u32,
    last: Option<Instant>,
}

impl Gpu {
    /// Reads what `wanted` asks for; `rows` are the tick's, and the
    /// per-process values stay readable through [`Gpu::dedicated`] and
    /// [`Gpu::shared`] until the next read.
    #[tracing::instrument(name = "gpu", level = "debug", skip_all)]
    pub fn read(&mut self, wanted: Wanted, rows: &[Row], handles: &Handles) -> Read {
        if self.enumerated.is_none_or(|at| at.elapsed() >= ENUMERATE_EVERY) {
            self.enumerate();
        }
        let engines = self.processes(wanted, rows, handles);
        Read {
            adapters: wanted
                .adapters
                .then(|| self.adapters.iter().map(Adapter::describe).collect()),
            engines: wanted.engines.then(|| engines.into()),
        }
    }

    /// Bytes the process has committed in the adapters' own memory as of
    /// the last read; [`NO_DATA_U64`] when it cannot be queried.
    pub fn dedicated(&self, row: &Row) -> u64 {
        self.used(row).map_or(NO_DATA_U64, |used| used.dedicated)
    }

    /// Bytes the process has committed in system memory the adapters map.
    pub fn shared(&self, row: &Row) -> u64 {
        self.used(row).map_or(NO_DATA_U64, |used| used.shared)
    }

    fn used(&self, row: &Row) -> Option<&Used> {
        self.processes
            .get(&row.pid)
            .filter(|used| used.sequence_number == row.sequence_number && used.listed == self.ticks)
    }

    #[tracing::instrument(name = "gpu adapters", level = "debug", skip_all)]
    fn enumerate(&mut self) {
        self.enumerated = Some(Instant::now());
        let mut query = D3DKMT_ENUMADAPTERS2::default();
        if unsafe { D3DKMTEnumAdapters2(&mut query) }.0 < 0 {
            return;
        }
        let mut found = vec![D3DKMT_ADAPTERINFO::default(); query.NumAdapters as usize];
        query.pAdapters = found.as_mut_ptr();
        let status = unsafe { D3DKMTEnumAdapters2(&mut query) };
        if status.0 < 0 {
            tracing::warn!(status = format_args!("{:#x}", status.0), "could not enumerate the GPU adapters");
            return;
        }
        found.truncate(query.NumAdapters as usize);
        let mut before = std::mem::take(&mut self.adapters);
        for info in found {
            let key = luid_key(info.AdapterLuid);
            if let Some(at) = before.iter().position(|old| old.key == key) {
                close(info.hAdapter);
                self.adapters.push(before.swap_remove(at));
            } else if let Some(adapter) = Adapter::open(info) {
                self.adapters.push(adapter);
            } else {
                close(info.hAdapter);
            }
        }
    }

    #[tracing::instrument(name = "gpu processes", level = "debug", skip_all)]
    fn processes(&mut self, wanted: Wanted, rows: &[Row], handles: &Handles) -> Vec<ProcessGpuEngine> {
        self.ticks += 1;
        let tick = self.ticks;
        let nodes_wanted = wanted.engines || wanted.adapters;
        let at = Instant::now();
        let since = self.last.map_or(Duration::ZERO, |last| at - last);
        self.last = Some(at);
        let (start, share, next) = turn(rows, self.cursor, since);
        self.cursor = next;
        let now = filetime_now();
        let young_for = (PROBE_ROUND.as_nanos() / 100) as u64;
        let Self {
            adapters,
            processes,
            scratch,
            ..
        } = self;
        let mut engines = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let used = processes.entry(row.pid).or_insert_with(|| Used {
                sequence_number: row.sequence_number,
                listed: tick,
                dedicated: 0,
                shared: 0,
                on: Vec::new(),
                checked: false,
            });
            if used.sequence_number != row.sequence_number {
                used.sequence_number = row.sequence_number;
                used.on.clear();
                used.checked = false;
            }
            used.listed = tick;
            let Some(handle) = handles.full(row.pid) else {
                used.dedicated = NO_DATA_U64;
                used.shared = NO_DATA_U64;
                used.on.clear();
                continue;
            };
            used.dedicated = 0;
            used.shared = 0;
            let young = now.saturating_sub(row.create_time) < young_for;
            if !due(used, young, in_turn(index, rows.len(), start, share)) {
                continue;
            }
            used.checked = true;
            for adapter in adapters.iter_mut() {
                let at = used.on.iter().position(|on| on.key == adapter.key);
                if wanted.memory {
                    match adapter.memory(handle) {
                        Some((dedicated, shared)) => {
                            used.dedicated += dedicated;
                            used.shared += shared;
                        }
                        None => {
                            if let Some(at) = at {
                                used.on.swap_remove(at);
                            }
                            continue;
                        }
                    }
                }
                let at = at.unwrap_or_else(|| {
                    used.on.push(On {
                        key: adapter.key,
                        nodes: Vec::new(),
                    });
                    used.on.len() - 1
                });
                if !nodes_wanted {
                    continue;
                }
                if !adapter.running(handle, scratch) {
                    used.on.swap_remove(at);
                    continue;
                }
                let on = &mut used.on[at];
                account(&mut adapter.nodes, &on.nodes, scratch);
                on.nodes.clone_from(scratch);
                if wanted.engines {
                    for (node, &running) in adapter.nodes.iter().zip(&on.nodes) {
                        if running != 0 {
                            engines.push(ProcessGpuEngine {
                                row: index as u32,
                                adapter_luid: adapter.key,
                                engine: node.ordinal,
                                running_time: running,
                            });
                        }
                    }
                }
            }
        }
        processes.retain(|_, used| used.listed == tick);
        engines
    }
}

/// Whether a process is read this tick: never read yet, with a context on
/// an adapter, young, or in its turn.
fn due(used: &Used, young: bool, in_turn: bool) -> bool {
    !used.checked || !used.on.is_empty() || young || in_turn
}

/// Now as a FILETIME, the clock `Row::create_time` is on.
fn filetime_now() -> u64 {
    const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    UNIX_EPOCH_AS_FILETIME + (since_epoch.as_nanos() / 100) as u64
}

/// Whether row `index` of `len` is among the `share` rows from `start`,
/// wrapping around.
fn in_turn(index: usize, len: usize, start: usize, share: usize) -> bool {
    (index + len - start) % len < share
}

/// Adds to each engine's total what a process ran on it since `before`, or
/// all it ran when there is no `before` for it: it is new to the engines.
/// A read that went backwards adds nothing.
fn account(nodes: &mut [Node], before: &[u64], now: &[u64]) {
    let known = before.len() == now.len();
    for (i, (node, &running)) in nodes.iter_mut().zip(now).enumerate() {
        let added = if known { running.wrapping_sub(before[i]) } else { running };
        if (added as i64) > 0 {
            node.total = node.total.wrapping_add(added);
        }
    }
}

impl Adapter {
    fn open(info: D3DKMT_ADAPTERINFO) -> Option<Self> {
        let handle = info.hAdapter;
        let mut kind = D3DKMT_ADAPTERTYPE::default();
        if query_info(handle, KMTQAITYPE_ADAPTERTYPE, &mut kind) < 0 || unsafe { kind.Anonymous.Value } & SOFTWARE_DEVICE != 0 {
            return None;
        }
        let (status, counts) = statistics(D3DKMT_QUERYSTATISTICS_ADAPTER, info.AdapterLuid, HANDLE::default(), 0);
        if status < 0 {
            return None;
        }
        let counts = unsafe { counts.QueryResult.AdapterInformation };
        let nodes = (0..counts.NodeCount)
            .map(|ordinal| {
                let mut meta = D3DKMT_NODEMETADATA {
                    NodeOrdinalAndAdapterIndex: ordinal,
                    ..Default::default()
                };
                let named = query_info(handle, KMTQAITYPE_NODEMETADATA, &mut meta) >= 0;
                let data = meta.NodeData;
                let (engine, friendly) = (data.EngineType, data.FriendlyName);
                let mut clocks = D3DKMT_NODE_PERFDATA {
                    NodeOrdinal: ordinal,
                    ..Default::default()
                };
                query_info(handle, KMTQAITYPE_NODEPERFDATA, &mut clocks);
                Node {
                    ordinal,
                    kind: if named { engine_kind(engine) } else { GpuEngineKind::Other },
                    name: if named { wide(&friendly).into() } else { SmolStr::default() },
                    max_frequency: clocks.MaxFrequency,
                    total: 0,
                }
            })
            .collect();
        let segments = (0..counts.NbSegments)
            .map(|id| {
                let (_, q) = statistics(D3DKMT_QUERYSTATISTICS_SEGMENT, info.AdapterLuid, HANDLE::default(), id);
                Segment {
                    id,
                    aperture: unsafe { q.QueryResult.SegmentInformation.Aperture } != 0,
                }
            })
            .collect();
        let mut sizes = D3DKMT_SEGMENTSIZEINFO::default();
        query_info(handle, KMTQAITYPE_GETSEGMENTSIZE, &mut sizes);
        Some(Self {
            handle,
            luid: info.AdapterLuid,
            key: luid_key(info.AdapterLuid),
            name: name(handle).into(),
            nodes,
            segments,
            shared_limit: sizes.SharedSystemMemorySize,
        })
    }

    /// The adapter as it is now, its engines as the processes' reads add up.
    fn describe(&self) -> GpuAdapter {
        let mut adapter = GpuAdapter {
            luid: self.key,
            name: self.name.clone(),
            shared_limit: self.shared_limit,
            engines: self
                .nodes
                .iter()
                .map(|node| GpuEngine {
                    ordinal: node.ordinal,
                    kind: node.kind,
                    name: node.name.clone(),
                    running_time: node.total,
                    frequency: 0,
                    max_frequency: node.max_frequency,
                })
                .collect(),
            ..Default::default()
        };
        for segment in &self.segments {
            let (status, q) = statistics(D3DKMT_QUERYSTATISTICS_SEGMENT, self.luid, HANDLE::default(), segment.id);
            if status < 0 {
                continue;
            }
            let info = unsafe { q.QueryResult.SegmentInformation };
            if segment.aperture {
                adapter.shared_usage += info.BytesResident;
            } else {
                adapter.dedicated_limit += info.CommitLimit;
                adapter.dedicated_usage += info.BytesResident;
            }
        }
        let mut perf = D3DKMT_ADAPTER_PERFDATA::default();
        if query_info(self.handle, KMTQAITYPE_ADAPTERPERFDATA, &mut perf) >= 0 {
            adapter.temperature = perf.Temperature;
            adapter.fan_rpm = perf.FanRPM;
            adapter.power = perf.Power;
            adapter.memory_frequency = perf.MemoryFrequency;
        }
        adapter
    }

    /// Committed bytes of the process in dedicated and in shared segments;
    /// None when it has no context on this adapter.
    fn memory(&self, process: HANDLE) -> Option<(u64, u64)> {
        let (mut dedicated, mut shared) = (0, 0);
        for segment in &self.segments {
            let (status, q) = statistics(D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT, self.luid, process, segment.id);
            if status < 0 {
                return None;
            }
            let committed = unsafe { q.QueryResult.ProcessSegmentInformation.BytesCommitted };
            if segment.aperture {
                shared += committed;
            } else {
                dedicated += committed;
            }
        }
        Some((dedicated, shared))
    }

    /// Reads every engine's time of the process into `nodes`; false when it
    /// has no context on this adapter.
    fn running(&self, process: HANDLE, nodes: &mut Vec<u64>) -> bool {
        nodes.clear();
        for node in &self.nodes {
            let (status, q) = statistics(D3DKMT_QUERYSTATISTICS_PROCESS_NODE, self.luid, process, node.ordinal);
            if status < 0 {
                return false;
            }
            nodes.push(unsafe { q.QueryResult.ProcessNodeInformation.RunningTime as u64 });
        }
        true
    }
}

fn luid_key(luid: LUID) -> u64 {
    (luid.HighPart as u32 as u64) << 32 | luid.LowPart as u64
}

fn close(adapter: D3DKMT_HANDLE) {
    let _ = unsafe { D3DKMTCloseAdapter(&D3DKMT_CLOSEADAPTER { hAdapter: adapter }) };
}

fn statistics(
    kind: D3DKMT_QUERYSTATISTICS_TYPE,
    luid: LUID,
    process: HANDLE,
    id: u32,
) -> (i32, D3DKMT_QUERYSTATISTICS) {
    let mut query: D3DKMT_QUERYSTATISTICS = unsafe { std::mem::zeroed() };
    query.Type = kind;
    query.AdapterLuid = luid;
    query.hProcess = process;
    query.Anonymous.QueryNode.NodeId = id;
    let status = unsafe { D3DKMTQueryStatistics(&query) };
    (status.0, query)
}

fn query_info<T>(adapter: D3DKMT_HANDLE, kind: KMTQUERYADAPTERINFOTYPE, value: &mut T) -> i32 {
    let mut query = D3DKMT_QUERYADAPTERINFO {
        hAdapter: adapter,
        Type: kind,
        pPrivateDriverData: (value as *mut T).cast(),
        PrivateDriverDataSize: size_of::<T>() as u32,
    };
    unsafe { D3DKMTQueryAdapterInfo(&mut query) }.0
}

fn name(adapter: D3DKMT_HANDLE) -> String {
    let mut description: Box<D3DKMT_DRIVER_DESCRIPTION> = Box::new(unsafe { std::mem::zeroed() });
    if query_info(adapter, KMTQAITYPE_DRIVER_DESCRIPTION, &mut *description) >= 0 {
        let name = wide(&description.DriverDescription);
        if !name.is_empty() {
            return name;
        }
    }
    let mut registry: Box<D3DKMT_ADAPTERREGISTRYINFO> = Box::new(unsafe { std::mem::zeroed() });
    if query_info(adapter, KMTQAITYPE_ADAPTERREGISTRYINFO, &mut *registry) >= 0 {
        return wide(&registry.AdapterString);
    }
    String::new()
}

fn wide(units: &[u16]) -> String {
    let end = units.iter().position(|&unit| unit == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

fn engine_kind(engine: i32) -> GpuEngineKind {
    match engine {
        1 => GpuEngineKind::ThreeD,
        2 => GpuEngineKind::VideoDecode,
        3 => GpuEngineKind::VideoEncode,
        4 => GpuEngineKind::VideoProcessing,
        5 => GpuEngineKind::SceneAssembly,
        6 => GpuEngineKind::Copy,
        7 => GpuEngineKind::Overlay,
        8 => GpuEngineKind::Crypto,
        9 => GpuEngineKind::VideoCodec,
        _ => GpuEngineKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Row {
        Row {
            pid: std::process::id(),
            sequence_number: 1,
            ..Default::default()
        }
    }

    const ALL: Wanted = Wanted {
        memory: true,
        engines: true,
        adapters: true,
    };

    fn nodes(count: u32) -> Vec<Node> {
        (0..count)
            .map(|ordinal| Node {
                ordinal,
                kind: GpuEngineKind::Other,
                name: SmolStr::default(),
                max_frequency: 0,
                total: 0,
            })
            .collect()
    }

    fn totals(nodes: &[Node]) -> Vec<u64> {
        nodes.iter().map(|node| node.total).collect()
    }

    #[test]
    fn an_engine_adds_up_what_its_processes_ran_since_they_were_last_read() {
        let mut engines = nodes(2);
        account(&mut engines, &[], &[100, 7]);
        assert_eq!(totals(&engines), [100, 7], "a process new to the engines brings all it ran");
        account(&mut engines, &[100, 7], &[130, 7]);
        account(&mut engines, &[], &[5, 0]);
        assert_eq!(totals(&engines), [135, 7]);
        account(&mut engines, &[130, 7], &[120, 9]);
        assert_eq!(totals(&engines), [135, 9], "a read that went backwards adds nothing");
    }

    #[test]
    fn a_turn_wraps_around_the_list() {
        let turn: Vec<usize> = (0..5).filter(|&i| in_turn(i, 5, 3, 3)).collect();
        assert_eq!(turn, [0, 3, 4]);
        assert!((0..5).all(|i| !in_turn(i, 5, 2, 0)), "no time, no turn");
        assert!((0..5).all(|i| in_turn(i, 5, 2, 5)));
    }

    #[test]
    fn an_idle_process_is_read_every_tick_while_young_then_in_its_turn() {
        let mut used = Used {
            sequence_number: 1,
            listed: 1,
            dedicated: 0,
            shared: 0,
            on: Vec::new(),
            checked: false,
        };
        assert!(due(&used, false, false), "never read");
        used.checked = true;
        assert!(due(&used, true, false), "young: most create their context now");
        assert!(!due(&used, false, false), "old and idle waits");
        assert!(due(&used, false, true), "until its turn");
        used.on.push(On { key: 1, nodes: Vec::new() });
        assert!(due(&used, false, false), "one with a context is read every tick");
    }

    #[test]
    fn a_process_is_young_by_its_creation_time() {
        let now = filetime_now();
        let ten_seconds = (PROBE_ROUND.as_nanos() / 100) as u64;
        assert!(now > 133_000_000_000_000_000, "after 2022 as a FILETIME");
        assert!(now.saturating_sub(now - ten_seconds / 2) < ten_seconds);
        assert!(now.saturating_sub(now - ten_seconds * 2) >= ten_seconds);
    }

    #[test]
    fn a_process_with_no_context_is_read_again_only_in_its_turn() {
        let mut handles = Handles::default();
        let rows = [me()];
        handles.sync(&rows);
        let mut gpu = Gpu::default();
        gpu.read(ALL, &rows, &handles);
        let used = &gpu.processes[&std::process::id()];
        assert!(used.checked && used.on.is_empty(), "read as it shows up and found idle");
        gpu.last = Some(Instant::now() + Duration::from_secs(3600));
        gpu.read(ALL, &rows, &handles);
        assert_eq!(gpu.dedicated(&rows[0]), 0, "out of turn it holds nothing, not no data");
    }

    #[test]
    fn a_time_the_kernel_keeps_below_zero_still_counts_as_it_grows() {
        let mut engines = nodes(1);
        let below = (-10_945_924_729i64) as u64;
        account(&mut engines, &[], &[below]);
        assert_eq!(totals(&engines), [0], "no sense in it on its own");
        account(&mut engines, &[below], &[below.wrapping_add(50)]);
        assert_eq!(totals(&engines), [50]);
    }

    #[test]
    fn every_hardware_adapter_names_its_engines_and_memory() {
        let mut gpu = Gpu::default();
        let read = gpu.read(
            Wanted {
                adapters: true,
                ..Default::default()
            },
            &[],
            &Handles::default(),
        );
        let adapters = read.adapters.expect("asked for");
        for adapter in adapters.iter() {
            assert!(!adapter.name.is_empty() && adapter.luid != 0);
            assert!(!adapter.name.contains("Basic Render"), "software adapters are left out");
            assert!(!adapter.engines.is_empty(), "{}", adapter.name);
            assert!(adapter.dedicated_usage <= adapter.dedicated_limit || adapter.dedicated_limit == 0);
        }
        assert!(read.engines.is_none(), "not asked for");
    }

    #[test]
    fn enumerating_again_keeps_the_adapters_it_knows() {
        let mut gpu = Gpu::default();
        gpu.enumerate();
        let before: Vec<(u64, u32)> = gpu.adapters.iter().map(|a| (a.key, a.handle.0)).collect();
        gpu.enumerate();
        let after: Vec<(u64, u32)> = gpu.adapters.iter().map(|a| (a.key, a.handle.0)).collect();
        assert_eq!(before, after, "the same adapters on the same handles");
    }

    #[test]
    fn a_process_without_a_gpu_context_uses_nothing_and_one_that_cannot_be_queried_has_no_data() {
        let mut handles = Handles::default();
        let rows = [me()];
        handles.sync(&rows);
        let mut gpu = Gpu::default();
        let read = gpu.read(ALL, &rows, &handles);
        assert_eq!((gpu.dedicated(&rows[0]), gpu.shared(&rows[0])), (0, 0), "a test binary draws nothing");
        assert!(read.engines.expect("asked for").is_empty());

        let other = Row {
            pid: 4,
            sequence_number: 9,
            ..Default::default()
        };
        gpu.read(ALL, &[other], &Handles::default());
        assert_eq!(gpu.dedicated(&other), NO_DATA_U64, "no handle, no data");
        assert_eq!(gpu.dedicated(&rows[0]), NO_DATA_U64, "not listed this tick");
    }

    #[test]
    fn an_engine_kind_follows_the_driver_type() {
        assert_eq!(engine_kind(1), GpuEngineKind::ThreeD);
        assert_eq!(engine_kind(6), GpuEngineKind::Copy);
        assert_eq!(engine_kind(42), GpuEngineKind::Other);
    }

    #[test]
    #[ignore = "requires admin and a desktop"]
    fn the_desktop_window_manager_draws_on_a_gpu() {
        let mut processes = crate::snapshot::Processes::new();
        processes.read().expect("elevated");
        let rows = processes.rows();
        let mut handles = Handles::default();
        handles.sync(rows);
        let mut gpu = Gpu::default();
        let first = gpu.read(ALL, rows, &handles);
        if first.adapters.as_ref().is_none_or(|a| a.is_empty()) {
            return;
        }
        let dwm = rows
            .iter()
            .position(|row| processes.image_name(row).eq_ignore_ascii_case("dwm.exe"))
            .expect("dwm");
        assert!(gpu.dedicated(&rows[dwm]) > 0, "dwm holds video memory");
        let engines = first.engines.as_ref().expect("asked for");
        assert!(engines.iter().any(|e| e.row as usize == dwm && e.running_time != 0));

        std::thread::sleep(Duration::from_millis(500));
        let second = gpu.read(ALL, rows, &handles);
        let busy = |read: &Read| -> u64 {
            read.adapters
                .as_ref()
                .unwrap()
                .iter()
                .flat_map(|a| a.engines.iter())
                .map(|e| e.running_time)
                .fold(0u64, u64::wrapping_add)
        };
        let ran = busy(&second).wrapping_sub(busy(&first));
        assert!(ran < 5_000_000 * 16, "{ran} over half a second is more than every engine running flat out");
    }
}
