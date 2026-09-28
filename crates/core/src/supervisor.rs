use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::Receiver;
use windows::Win32::HANDLE;

use crate::etw::router::KernelRouter;
use crate::model::{ProcessPriority, ProcessState};
use crate::probes::{self, Handles};
use crate::providers::disk::KernelDiskProvider;
use crate::providers::machine::MachineProbe;
use crate::providers::network::KernelNetworkProvider;
use crate::providers::process::passport::SidNames;
use crate::providers::process::{self, Images};
use crate::providers::provider::Provider;
use crate::report::{Diff, Health};
use crate::sample::{
    Columns, Demand, Extras, MachineSample, MetricSpec, NO_DATA_U32, ProcessMetrics, Sample, now_100ns,
};
use crate::sink::Sink;
use crate::snapshot::{self, Processes, Row};
use crate::state::SystemState;
use crate::state::events::StateChange;
use crate::state::process::Sighted;

/// The longest the first snapshot waits for its images' verdicts.
const FIRST_VERDICTS: Duration = Duration::from_secs(60);

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
/// that is due for a sample also reads every process and the machine.
pub struct Supervisor {
    router: KernelRouter,
    sink: Sink,
    rx: Receiver<StateChange>,
    providers: Vec<Box<dyn Provider>>,
    reader: Reader,
    demand: Demand,
    sampled: Instant,
    sampled_for: MetricSpec,
    snapshot_error: Option<String>,
}

struct Reader {
    images: Images,
    names: SidNames,
    state: SystemState,
    processes: Processes,
    handles: Handles,
    machine: MachineProbe,
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

        let mut builder = KernelRouter::builder();
        if let Some(prefix) = &config.session_namespace {
            builder.session_namespace(prefix);
        }
        for p in &providers {
            p.register(&mut builder)?;
        }

        let router = builder.start(sink.clone())?;

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
            snapshots: 0,
            session: probes::own_session(),
            fresh: None,
        };
        let spec = demand.get();
        let sampled = Instant::now();
        let mut supervisor = Self {
            router,
            sink,
            rx,
            providers,
            reader,
            demand,
            sampled,
            sampled_for: spec,
            snapshot_error: None,
        };
        supervisor.reader.sample(&spec).context("the first snapshot")?;
        supervisor.reader.await_verdicts(sampled + FIRST_VERDICTS);
        Ok(supervisor)
    }

    /// Applies what the providers sent since the last tick, samples when a
    /// sample is [`due`](Self::due) or the last one does not cover the
    /// demand, and adds what changed to `diff`, which whoever applies it
    /// empties before the next tick. The first tick hands on everything.
    pub fn tick(&mut self, diff: &mut Diff) {
        for change in self.rx.try_iter() {
            self.reader.state.apply(change);
        }
        for image in self.reader.images.judged() {
            self.reader.state.judge(image);
        }

        let spec = self.demand.get();
        let grown = !self.sampled_for.covers(&spec);
        let on_time = self.sampled.elapsed() >= spec.period();
        if on_time {
            self.sampled = Instant::now();
        }
        if grown || on_time {
            self.sampled_for = spec;
            match self.reader.sample(&spec) {
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

    /// What the core says about itself now.
    pub fn health(&self) -> Health {
        Health {
            dropped_by_sink: self.sink.dropped(),
            sessions: self.router.health(),
            snapshot_error: self.snapshot_error.clone(),
            taken_at: Instant::now(),
        }
    }

    /// When the next sample is due: a period of the demand as it is now
    /// after the last one taken on time. A sample taken because the demand
    /// grew does not move it.
    pub fn due(&self) -> Instant {
        self.sampled + self.demand.get().period()
    }
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

    #[tracing::instrument(level = "debug", skip_all)]
    fn sample(&mut self, spec: &MetricSpec) -> Result<()> {
        self.processes.read()?;
        let sampled_at = now_100ns();

        let snapshot = &self.processes;
        let rows = snapshot.rows();
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
                        snapshot.user_sid(row).as_deref(),
                        (snapshot.package_full_name(row), snapshot.app_id(row)),
                        names,
                    ),
                }
            },
            |request| images.ask(request),
        );

        self.handles.sync(rows);
        observe(&mut self.state, &self.handles, rows);

        let columns = columns(
            spec.processes,
            rows,
            &Beside {
                handles: &self.handles,
                session: self.session,
                state: &self.state,
            },
        );
        let machine = if spec.machine.is_empty() {
            MachineSample::default()
        } else {
            self.machine.sample(spec.machine, self.state.machine_totals())
        };

        self.snapshots += 1;
        let sample = Sample {
            snapshot: self.snapshots,
            sampled_at,
            period: spec.period(),
            wanted: *spec,
            passport_etag: 0,
            pids: rows.iter().map(|r| r.pid).collect(),
            sequence_numbers: rows.iter().map(|r| r.sequence_number).collect(),
            columns,
            machine,
        };
        self.fresh = Some(Arc::new(sample));
        Ok(())
    }
}

#[tracing::instrument(name = "states", level = "debug", skip_all)]
fn observe(state: &mut SystemState, handles: &Handles, rows: &[Row]) {
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
    #[ignore = "requires admin and a real ETW session"]
    fn the_first_tick_hands_on_everything_and_its_sample_covers_exactly_that() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new(MetricSpec {
            interval: Duration::from_millis(200),
            processes: ProcessMetrics::all(),
            machine: MachineMetrics::all(),
        });
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
    fn a_tick_before_the_sample_is_due_hands_on_no_sample() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new(MetricSpec {
            interval: Duration::from_secs(60),
            processes: ProcessMetric::Handles.into(),
            machine: MachineMetric::Cpu.into(),
        });
        let before = Instant::now();
        let mut supervisor = Supervisor::start(config(), demand, || {}).expect("elevated");
        let first = tick(&mut supervisor);
        let again = tick(&mut supervisor);
        assert!(again.sample.is_none());
        assert!(supervisor.due() >= before + Duration::from_secs(60));
        assert_eq!(first.sample.unwrap().columns.working_set, None, "not asked for");
    }
}
