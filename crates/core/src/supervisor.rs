use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::Receiver;
use windows::Win32::HANDLE;

use crate::etw::router::KernelRouter;
use crate::etw::vars::FLUSH_TIMER_MS;
use crate::model::{ProcessPriority, ProcessState};
use crate::probes::{self, Handles};
use crate::providers::disk::KernelDiskProvider;
use crate::providers::gpu::{self, Gpu};
use crate::providers::machine::MachineProbe;
use crate::providers::mapped::Mapped;
use crate::providers::network::KernelNetworkProvider;
use crate::providers::process::passport::SidNames;
use crate::providers::process::{self, Images};
use crate::providers::provider::Provider;
use crate::providers::vm_host::VmHosts;
use crate::report::{Diff, Health};
use crate::sample::{
    Columns, Demand, Extras, MAX_INTERVAL, MachineMetric, MachineSample, MetricSpec, NO_DATA_U32, ProcessMetric,
    ProcessMetrics, Sample, now_100ns,
};
use crate::schedule::Schedule;
use crate::sink::Sink;
use crate::snapshot::{self, Processes, Row};
use crate::state::SystemState;
use crate::state::events::StateChange;
use crate::state::process::Sighted;

/// The longest the first snapshot waits for its images' verdicts.
const FIRST_VERDICTS: Duration = Duration::from_secs(60);

/// How often the core looks whether its sessions still run, and starts them
/// again when they do not.
const SESSIONS_CHECKED: Duration = Duration::from_secs(30);

/// The longest ETW holds a buffer that is not full yet.
const SLOWEST_FLUSH_MS: u32 = 1000;

/// What one running core names on the machine. Two cores with different
/// configs do not touch each other; a second one with the same config takes
/// the first one's sessions.
#[derive(Clone, Debug)]
pub struct SupervisorConfig {
    /// Prefix of its ETW sessions' names; None for the plain names.
    pub session_namespace: Option<String>,
    /// Name of the store signature verdicts persist in.
    pub signature_store: String,
}

/// Owns the machine's current picture and the sessions that feed it. Every
/// tick applies what the providers sent and hands on what changed; a tick
/// that is due for a sample reads what the due intervals want: the machine,
/// and every process unless they want the machine alone.
pub struct Supervisor {
    /// None while the sessions could not be started; disk and network stay
    /// silent then and everything else goes on.
    router: Option<KernelRouter>,
    sessions_checked: Instant,
    session_namespace: Option<String>,
    sink: Sink,
    rx: Receiver<StateChange>,
    providers: Vec<Box<dyn Provider>>,
    reader: Reader,
    demand: Demand,
    schedule: Schedule,
    /// What the sessions' flush timer was last set to, in milliseconds.
    flush_timer: u32,
    snapshot_error: Option<String>,
}

struct Reader {
    images: Images,
    names: SidNames,
    state: SystemState,
    processes: Processes,
    handles: Handles,
    machine: MachineProbe,
    gpu: Gpu,
    mapped: Mapped,
    vm_hosts: VmHosts,
    snapshots: u64,
    session: Option<u32>,
    fresh: Option<Arc<Sample>>,
}

impl Supervisor {
    /// Starts the sessions and providers and takes the first sample, which
    /// waits for the verdicts on its images (up to [`FIRST_VERDICTS`]).
    /// `demand` says what to sample and how often; whoever keeps the
    /// subscribers changes it. `wake` asks whoever ticks for a tick now:
    /// a verdict came in, or events pile up.
    pub fn start(config: SupervisorConfig, demand: Demand, wake: impl Fn() + Send + Sync + 'static) -> Result<Self> {
        if let Err(error) = crate::privileges::enable(windows::core::w!("SeDebugPrivilege")) {
            tracing::warn!(%error, "running without SeDebugPrivilege: other accounts' processes stay opaque");
        }

        let wake = Arc::new(wake);
        let images = Images::start(&config.signature_store, {
            let wake = wake.clone();
            move || wake()
        })?;
        let providers: Vec<Box<dyn Provider>> = vec![
            Box::new(KernelDiskProvider::new()),
            Box::new(KernelNetworkProvider::new()),
        ];
        let (sink, rx) = Sink::bounded(crate::sink::DEFAULT_CAPACITY, move || wake());

        let router = match start_router(&providers, config.session_namespace.as_deref(), &sink) {
            Ok(router) => Some(router),
            Err(error) => {
                tracing::warn!(error = format!("{error:#}"), "disk and network stay silent until the sessions start");
                None
            }
        };

        for (started, p) in providers.iter().enumerate() {
            if let Err(e) = p.start(sink.clone()) {
                for already_started in providers[..started].iter().rev() {
                    already_started.stop();
                }
                return Err(e);
            }
        }

        let reader = Reader {
            images,
            names: SidNames::default(),
            state: SystemState::new(),
            processes: Processes::new(),
            handles: Handles::default(),
            machine: MachineProbe::new(),
            gpu: Gpu::default(),
            mapped: Mapped::start()?,
            vm_hosts: VmHosts::start()?,
            snapshots: 0,
            session: probes::own_session(),
            fresh: None,
        };
        let sampled = Instant::now();
        let mut schedule = Schedule::default();
        let first = schedule.take(&demand.get(), sampled).map_or_else(MetricSpec::default, |due| due.spec);
        let mut supervisor = Self {
            router,
            sessions_checked: sampled,
            session_namespace: config.session_namespace,
            sink,
            rx,
            providers,
            reader,
            demand,
            schedule,
            flush_timer: FLUSH_TIMER_MS,
            snapshot_error: None,
        };
        supervisor.reader.sample(&first, true).context("the first snapshot")?;
        supervisor.reader.await_verdicts(sampled + FIRST_VERDICTS);
        Ok(supervisor)
    }

    /// Applies what the providers sent since the last tick, samples for the
    /// intervals that are due or want more than they were last sampled for,
    /// and adds what changed to `diff`, which whoever applies it empties
    /// before the next tick. The first tick hands on everything, the first
    /// sample among it, and samples nothing more itself.
    pub fn tick(&mut self, diff: &mut Diff) {
        self.keep_sessions();
        let specs = self.demand.get();
        if let Some(router) = &self.router {
            let flush_timer = flush_timer_for(&specs);
            if flush_timer != self.flush_timer {
                if let Err(error) = router.set_flush_timer(flush_timer) {
                    tracing::warn!(error = format!("{error:#}"), flush_timer, "the sessions keep their flush timer");
                }
                self.flush_timer = flush_timer;
            }
            router.flush();
        }
        for change in self.rx.try_iter() {
            self.reader.state.apply(change);
        }
        for image in self.reader.images.judged() {
            self.reader.state.judge(image);
        }

        if self.reader.fresh.is_none()
            && let Some(due) = self.schedule.take(&specs, Instant::now())
        {
            match self.reader.sample(&due.spec, due.reads_processes) {
                Ok(()) => {
                    if self.snapshot_error.take().is_some() {
                        tracing::info!("the process list reads again");
                    }
                }
                Err(error) => {
                    let error = format!("{error:#}");
                    if self.snapshot_error.is_none() {
                        tracing::warn!(%error, "could not read the process list; the picture stays as it was");
                    }
                    self.snapshot_error = Some(error);
                }
            }
        }
        self.reader.state.take(diff);
        diff.sample = self.reader.fresh.take();
    }

    /// Every [`SESSIONS_CHECKED`], starts the sessions again when one was
    /// stopped from outside, taken by another core or never came up.
    fn keep_sessions(&mut self) {
        if self.sessions_checked.elapsed() < SESSIONS_CHECKED {
            return;
        }
        self.sessions_checked = Instant::now();
        if self.router.as_ref().is_some_and(KernelRouter::healthy) {
            return;
        }
        self.router = None;
        match start_router(&self.providers, self.session_namespace.as_deref(), &self.sink) {
            Ok(router) => {
                tracing::info!("the sessions run again");
                self.router = Some(router);
                self.flush_timer = FLUSH_TIMER_MS;
            }
            Err(error) => tracing::warn!(error = format!("{error:#}"), "the sessions still do not start"),
        }
    }

    /// What the core says about itself now.
    pub fn health(&self) -> Health {
        Health {
            dropped_by_sink: self.sink.dropped(),
            sessions: self.router.as_ref().map_or_else(Vec::new, KernelRouter::health),
            snapshot_error: self.snapshot_error.clone(),
            taken_at: Instant::now(),
        }
    }

    /// When the next sample is due: the soonest interval's period after it
    /// was last sampled on time. A sample taken because an interval wants
    /// more does not move it; a change of the demand wakes the core anyway.
    pub fn due(&self) -> Instant {
        self.schedule.due().unwrap_or_else(|| Instant::now() + MAX_INTERVAL)
    }
}

/// How many milliseconds ETW may hold a buffer that is not full yet: half
/// the fastest interval, so a sample sees the events from before the last
/// one, and never longer than [`SLOWEST_FLUSH_MS`]. A short timer costs a
/// wake of the reading thread per processor per flush.
fn flush_timer_for(specs: &[MetricSpec]) -> u32 {
    specs
        .iter()
        .map(MetricSpec::period)
        .min()
        .map_or(SLOWEST_FLUSH_MS, |period| (period / 2).as_millis() as u32)
        .clamp(FLUSH_TIMER_MS, SLOWEST_FLUSH_MS)
}

fn start_router(providers: &[Box<dyn Provider>], namespace: Option<&str>, sink: &Sink) -> Result<KernelRouter> {
    let mut builder = KernelRouter::builder();
    if let Some(prefix) = namespace {
        builder.session_namespace(prefix);
    }
    for p in providers {
        p.register(&mut builder)?;
    }
    builder.start(sink.clone())
}

impl Reader {
    #[tracing::instrument(name = "first verdicts", level = "debug", skip_all)]
    fn await_verdicts(&mut self, deadline: Instant) {
        while self.state.pending_images().next().is_some() {
            match self.images.next(deadline.saturating_duration_since(Instant::now())) {
                Some(image) => self.state.judge(image),
                None => {
                    let pending: Vec<&str> = self.state.pending_images().collect();
                    tracing::warn!(?pending, "the first snapshot went out before these images were judged");
                    break;
                }
            }
        }
    }

    /// Reads what `spec` wants; without `reads_processes` only the machine,
    /// and the sample has no rows.
    #[tracing::instrument(level = "debug", skip_all)]
    fn sample(&mut self, spec: &MetricSpec, reads_processes: bool) -> Result<()> {
        if reads_processes {
            self.processes.read()?;
        }
        let sampled_at = now_100ns();

        let snapshot = &self.processes;
        let rows = snapshot.rows();
        if reads_processes {
            let names = &mut self.names;
            let images = &self.images;
            self.state.reconcile(
                rows,
                |row| {
                    let image_name = snapshot.image_name(row);
                    Sighted {
                        is_kernel_process: snapshot::is_kernel_pseudo_process(row.pid, row.parent_pid, &image_name),
                        image_name: image_name.into(),
                        read: process::read(
                            row.pid,
                            row.sequence_number,
                            snapshot.user_sid(row).as_deref(),
                            (snapshot.package_full_name(row), snapshot.app_id(row)),
                            names,
                        ),
                    }
                },
                |request| images.ask(request),
            );

            self.handles.sync(rows);
            self.vm_hosts.read(rows);
            observe(&mut self.state, &self.handles, &self.vm_hosts, rows);
        }

        let wanted = gpu::Wanted {
            memory: spec.processes.contains(ProcessMetric::GpuDedicated)
                || spec.processes.contains(ProcessMetric::GpuShared),
            engines: spec.processes.contains(ProcessMetric::GpuEngines),
            adapters: spec.machine.contains(MachineMetric::Gpu),
        };
        if reads_processes && spec.processes.contains(ProcessMetric::ExclusiveMapped) {
            self.mapped.read(rows);
        }
        let gpu = if wanted.any() {
            self.gpu.read(wanted, rows, &self.handles)
        } else {
            gpu::Read::default()
        };

        let columns = columns(
            spec.processes,
            rows,
            &Beside {
                handles: &self.handles,
                session: self.session,
                state: &self.state,
                gpu: &self.gpu,
                mapped: &self.mapped,
            },
        );
        let mut machine = if spec.machine.is_empty() {
            MachineSample::default()
        } else {
            self.machine.sample(spec.machine, self.state.machine_totals())
        };
        machine.gpus = gpu.adapters;

        self.snapshots += 1;
        let sample = Sample {
            snapshot: self.snapshots,
            sampled_at,
            period: spec.period(),
            wanted: *spec,
            passport_etag: 0,
            pids: if reads_processes { rows.iter().map(|r| r.pid).collect() } else { Arc::from([]) },
            sequence_numbers: if reads_processes {
                rows.iter().map(|r| r.sequence_number).collect()
            } else {
                Arc::from([])
            },
            columns,
            gpu_engines: gpu.engines,
            machine,
        };
        self.fresh = Some(Arc::new(sample));
        Ok(())
    }
}

#[tracing::instrument(name = "states", level = "debug", skip_all)]
fn observe(state: &mut SystemState, handles: &Handles, vm_hosts: &VmHosts, rows: &[Row]) {
    for row in rows {
        let probed = handles.probed(row.pid);
        let base_priority = ProcessPriority::from_base(row.base_priority);
        state.observe(ProcessState {
            pid: row.pid,
            sequence_number: row.sequence_number,
            suspended: Some(row.suspended),
            efficiency_mode: probed
                .power_throttling
                .zip(base_priority)
                .map(|(eco, base)| eco && base == ProcessPriority::Idle),
            base_priority,
            power_throttling: probed.power_throttling,
            job_object_id: row.job_object_id,
            io_priority: probed.io_priority,
            vm_host: vm_hosts.get(row),
        });
    }
}

#[tracing::instrument(level = "debug", skip_all)]
fn columns(wanted: ProcessMetrics, rows: &[Row], beside: &Beside) -> Columns {
    Columns::build(wanted, rows, beside)
}

struct Beside<'a> {
    handles: &'a Handles,
    session: Option<u32>,
    state: &'a SystemState,
    gpu: &'a Gpu,
    mapped: &'a Mapped,
}

impl Beside<'_> {
    fn gui(&self, row: &Row, count: fn(HANDLE) -> u32) -> u32 {
        match self.handles.get(row.pid) {
            Some(handle) if self.session == Some(row.session_id) => count(handle),
            _ => NO_DATA_U32,
        }
    }
}

impl Extras for Beside<'_> {
    fn user_objects(&self, row: &Row) -> u32 {
        self.gui(row, probes::user_objects)
    }

    fn gdi_objects(&self, row: &Row) -> u32 {
        self.gui(row, probes::gdi_objects)
    }

    fn net_rx_bytes(&self, row: &Row) -> u64 {
        self.state.network(row.pid, row.sequence_number).recv_bytes
    }

    fn net_tx_bytes(&self, row: &Row) -> u64 {
        self.state.network(row.pid, row.sequence_number).sent_bytes
    }

    fn gpu_dedicated(&self, row: &Row) -> u64 {
        self.gpu.dedicated(row)
    }

    fn gpu_shared(&self, row: &Row) -> u64 {
        self.gpu.shared(row)
    }

    fn exclusive_mapped(&self, row: &Row) -> u64 {
        self.mapped.get(row)
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        for provider in self.providers.iter().rev() {
            provider.stop();
        }
        let dropped = self.sink.dropped();
        if dropped > 0 {
            tracing::warn!("events dropped by sink: {dropped}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::{MachineMetric, MachineMetrics, ProcessMetric};
    use std::time::Duration;

    fn config() -> SupervisorConfig {
        SupervisorConfig {
            session_namespace: Some("Uniproc-SupervisorTest-".into()),
            signature_store: "signatures-supervisor-test".into(),
        }
    }

    fn tick(supervisor: &mut Supervisor) -> Diff {
        let mut diff = Diff::default();
        supervisor.tick(&mut diff);
        diff.passports.sort_unstable_by_key(|p| p.pid);
        diff.states.sort_unstable_by_key(|s| s.pid);
        diff
    }

    #[test]
    fn the_flush_timer_follows_the_fastest_interval_within_its_bounds() {
        let at = |intervals: &[u64]| {
            let specs: Vec<MetricSpec> =
                intervals.iter().map(|&ms| MetricSpec::idle(Duration::from_millis(ms))).collect();
            flush_timer_for(&specs)
        };
        assert_eq!(at(&[]), SLOWEST_FLUSH_MS, "nobody subscribed");
        assert_eq!(at(&[1000]), 500);
        assert_eq!(at(&[5000, 1000]), 500, "the fastest decides");
        assert_eq!(at(&[0]), FLUSH_TIMER_MS, "the shortest interval");
        assert_eq!(at(&[60_000]), SLOWEST_FLUSH_MS);
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn the_first_tick_hands_on_everything_and_its_sample_covers_exactly_that() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new([MetricSpec {
            interval: Duration::from_millis(200),
            processes: ProcessMetrics::all(),
            machine: MachineMetrics::all(),
        }]);
        let mut supervisor = Supervisor::start(config(), demand, || {}).expect("elevated");

        let first = tick(&mut supervisor);
        let sample = first.sample.as_ref().expect("the first sample");
        let pids: Vec<u32> = first.passports.iter().map(|p| p.pid).collect();
        assert_eq!(*sample.pids, *pids);
        assert_eq!(first.states.iter().map(|s| s.pid).collect::<Vec<_>>(), pids);
        assert_eq!(sample.columns.working_set.as_ref().unwrap().len(), pids.len());
        let listed: Vec<(u32, u64)> = sample.pids.iter().copied().zip(sample.sequence_numbers.iter().copied()).collect();
        assert!(first.gone.iter().all(|gone| !listed.contains(gone)), "what left is not in the sample");
        assert!(first.passports.iter().all(|p| p.sequence_number == 0 || !p.user.is_empty() || p.is_kernel_process));

        let me = pids.iter().position(|&pid| pid == std::process::id()).unwrap();
        assert!(first.states[me].io_priority != crate::model::IoPriority::Unknown);

        std::thread::sleep(supervisor.due().saturating_duration_since(Instant::now()));
        let second = tick(&mut supervisor);
        let next = second.sample.as_ref().expect("due again");
        assert_eq!(next.snapshot, sample.snapshot + 1);
        assert!(next.sampled_at > sample.sampled_at);
        let me = next.pids.iter().position(|&pid| pid == std::process::id()).unwrap();
        let columns = &next.columns;
        assert!(columns.cpu_user_time.as_ref().unwrap()[me] + columns.cpu_kernel_time.as_ref().unwrap()[me] > 0);
        assert!(columns.private_working_set.as_ref().unwrap()[me] > 0);
        assert!(columns.handles.as_ref().unwrap()[me] > 0);
        assert!(next.machine.cpu.is_some() && next.machine.memory.is_some());
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_session_stopped_from_outside_is_started_again() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new([MetricSpec {
            interval: Duration::from_secs(60),
            processes: ProcessMetrics::empty(),
            machine: MachineMetric::Disk.into(),
        }]);
        let mut supervisor = Supervisor::start(config(), demand, || {}).expect("elevated");
        let name = supervisor.health().sessions[0].name.clone();
        let stopped = std::process::Command::new("logman")
            .args(["stop", &name, "-ets"])
            .output()
            .expect("logman stop");
        assert!(stopped.status.success(), "{stopped:?}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while supervisor.health().sessions[0].is_healthy() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!supervisor.health().sessions[0].is_healthy());

        supervisor.sessions_checked = Instant::now() - SESSIONS_CHECKED;
        tick(&mut supervisor);
        let sessions = supervisor.health().sessions;
        assert!(sessions.iter().all(|s| s.is_healthy()), "{sessions:?}");
        assert_eq!(sessions[0].name, name);
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_tick_before_the_sample_is_due_hands_on_no_sample() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new([MetricSpec {
            interval: Duration::from_secs(60),
            processes: ProcessMetric::Handles.into(),
            machine: MachineMetric::Cpu.into(),
        }]);
        let before = Instant::now();
        let mut supervisor = Supervisor::start(config(), demand, || {}).expect("elevated");
        let first = tick(&mut supervisor);
        let again = tick(&mut supervisor);
        assert!(again.sample.is_none());
        assert!(supervisor.due() >= before + Duration::from_secs(60));
        assert_eq!(first.sample.unwrap().columns.working_set, None, "not asked for");
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn the_machine_is_read_on_its_own_interval_without_the_processes() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new([
            MetricSpec {
                interval: Duration::from_millis(100),
                processes: ProcessMetrics::empty(),
                machine: MachineMetric::Cpu | MachineMetric::Memory,
            },
            MetricSpec {
                interval: Duration::from_secs(60),
                processes: ProcessMetric::Handles.into(),
                machine: MachineMetrics::empty(),
            },
        ]);
        let mut supervisor = Supervisor::start(config(), demand, || {}).expect("elevated");
        let first = tick(&mut supervisor);
        assert!(!first.sample.unwrap().pids.is_empty());

        std::thread::sleep(supervisor.due().saturating_duration_since(Instant::now()));
        let fast = tick(&mut supervisor);
        let sample = fast.sample.expect("the machine is due");
        assert!(sample.pids.is_empty() && sample.columns.handles.is_none(), "no process read");
        assert!(sample.machine.cpu.is_some() && sample.machine.memory.is_some());
        assert!(supervisor.due() <= Instant::now() + Duration::from_millis(100));
    }
}
