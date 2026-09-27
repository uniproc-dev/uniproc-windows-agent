use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use fxhash::FxHashMap;

use crate::etw::router::KernelRouter;
use crate::model::{ProcessPriority, ProcessState};
use crate::probes::{self, Handles};
use crate::providers::disk::KernelDiskProvider;
use crate::providers::machine::MachineProbe;
use crate::providers::network::KernelNetworkProvider;
use crate::providers::process::Enricher;
use crate::providers::provider::Provider;
use crate::report::{self, Process, ProbeCost, Report};
use crate::sample::{
    Columns, Demand, MachineSample, MetricSpec, ProcessMetric, ProcessMetrics, Sample, Source, now_100ns,
};
use crate::sink::Sink;
use crate::snapshot::{self, Processes, Row};
use crate::state::SystemState;
use crate::state::events::{EnrichRequest, StateChange};
use crate::state::process::Sighted;
use uniproc_agent_kit::Tagged;

/// A sample this close to due is taken now rather than a period late.
const DUE_TOLERANCE: Duration = Duration::from_millis(5);

struct Sampled {
    processes: Tagged<Arc<[Process]>>,
    states: Arc<[ProcessState]>,
    sample: Arc<Sample>,
}

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

/// Owns the machine's state. Every tick applies what the providers sent;
/// a tick that is due for a sample also reads every process and the machine.
pub struct Supervisor {
    providers: Vec<Box<dyn Provider>>,
    enrich: Sender<EnrichRequest>,
    state: SystemState,
    processes: Processes,
    handles: Handles,
    machine: MachineProbe,
    demand: Demand,
    snapshots: u64,
    sampled: Option<Instant>,
    sees_gui: bool,
    costs: Vec<ProbeCost>,
    router: Option<KernelRouter>,
    sink: Option<Sink>,
    rx: Option<Receiver<StateChange>>,
    config: SupervisorConfig,
    last: Option<Arc<Report>>,
    running: bool,
}

impl Supervisor {
    /// Nothing runs until [`start`](Self::start). `demand` says what to
    /// sample and how often; whoever keeps the subscribers changes it.
    pub fn new(config: SupervisorConfig, demand: Demand) -> Self {
        let enricher = Enricher::new(config.signature_store.clone());
        let enrich = enricher.queue();
        Self {
            providers: vec![
                Box::new(KernelDiskProvider::new()),
                Box::new(KernelNetworkProvider::new()),
                Box::new(enricher),
            ],
            enrich,
            state: SystemState::new(),
            processes: Processes::new(),
            handles: Handles::default(),
            machine: MachineProbe::new(),
            demand,
            snapshots: 0,
            sampled: None,
            sees_gui: probes::sees_gui_objects(),
            costs: Vec::new(),
            router: None,
            sink: None,
            rx: None,
            config,
            last: None,
            running: false,
        }
    }

    /// Starts the sessions and providers. The calling thread is the one woken
    /// to tick when events pile up, so it should be the one that ticks.
    pub fn start(&mut self) -> Result<()> {
        if let Err(error) = crate::privileges::enable(windows::core::w!("SeDebugPrivilege")) {
            tracing::warn!(%error, "running without SeDebugPrivilege: other accounts' processes stay opaque");
        }

        let (sink, rx) = Sink::bounded(crate::sink::DEFAULT_CAPACITY);
        sink.set_drainer(std::thread::current());

        let mut builder = KernelRouter::builder();
        if let Some(prefix) = &self.config.session_namespace {
            builder.session_namespace(prefix);
        }
        for p in &self.providers {
            p.register(&mut builder)?;
        }

        let router = builder.start(sink.clone())?;

        for (started, p) in self.providers.iter().enumerate() {
            if let Err(e) = p.start(sink.clone()) {
                for already_started in self.providers[..started].iter().rev() {
                    already_started.stop();
                }
                return Err(e);
            }
        }

        self.router = Some(router);
        self.sink = Some(sink);
        self.rx = Some(rx);
        self.running = true;
        Ok(())
    }

    /// Applies what the providers sent since the last tick, samples when a
    /// sample is due, and reports the result.
    pub fn tick(&mut self) -> Arc<Report> {
        if let Some(rx) = self.rx.take() {
            for change in rx.try_iter() {
                self.state.apply(change);
            }
            self.rx = Some(rx);
        }

        let spec = self.demand.now();
        let grown = self.demand.take_grown();
        let on_time = self
            .sampled
            .is_none_or(|at| at.elapsed() + DUE_TOLERANCE >= spec.period());
        if on_time {
            self.sampled = Some(Instant::now());
        }
        let due = grown || on_time;
        let previous = self.last.clone();
        let previous = previous.as_deref();
        let sampled = match previous {
            Some(previous) if !due => Sampled {
                processes: report::processes(&self.state, Some(&previous.processes)),
                states: previous.states.clone(),
                sample: previous.sample.clone(),
            },
            _ => self.sample(&spec, previous.map(|p| &p.processes)),
        };

        let report = Arc::new(Report {
            processes: sampled.processes,
            states: sampled.states,
            sample: sampled.sample,
            dropped_by_sink: self.sink.as_ref().map_or(0, Sink::dropped),
            sessions: self.router.as_ref().map_or_else(Vec::new, KernelRouter::health),
            costs: self.costs.clone(),
            taken_at: Instant::now(),
        });
        self.last = Some(report.clone());
        report
    }

    fn time<T>(&mut self, name: &'static str, probe: impl FnOnce(&mut Self) -> T) -> T {
        let started = Instant::now();
        let out = probe(self);
        let took = started.elapsed();
        match self.costs.iter_mut().find(|c| c.name == name) {
            Some(cost) => cost.record(took),
            None => {
                let mut cost = ProbeCost {
                    name,
                    ..Default::default()
                };
                cost.record(took);
                self.costs.push(cost);
            }
        }
        out
    }

    fn sample(
        &mut self,
        spec: &MetricSpec,
        previous: Option<&Tagged<Arc<[Process]>>>,
    ) -> Sampled {
        if let Err(error) = self.time("snapshot", |s| s.processes.read()) {
            tracing::warn!(%error, "could not read the process list");
        }
        let sampled_at = now_100ns();

        let snapshot = &self.processes;
        let added = self.state.reconcile(snapshot.rows(), |row| {
            let image_name = snapshot.image_name(row);
            Sighted {
                is_kernel_process: snapshot::is_kernel_pseudo_process(row.pid, row.parent_pid, &image_name),
                image_name,
                package_full_name: snapshot.package_full_name(row),
                package_relative_app_id: snapshot.app_id(row),
            }
        });
        for row in added {
            let entry = self.state.process(row.pid);
            let _ = self.enrich.send(EnrichRequest {
                pid: row.pid,
                sequence_number: row.sequence_number,
                user_sid: snapshot.user_sid(row),
                package_full_name: entry.map(|e| e.package_name.clone()).unwrap_or_default(),
                package_relative_app_id: entry.map(|e| e.package_relative_app_id.clone()).unwrap_or_default(),
            });
        }

        self.time("handles", |s| s.handles.sync(s.processes.rows()));
        let processes = report::processes(&self.state, previous);
        let at: FxHashMap<u32, usize> = self
            .processes
            .rows()
            .iter()
            .enumerate()
            .map(|(i, row)| (row.pid, i))
            .collect();
        let rows: Vec<Row> = processes
            .value
            .iter()
            .map(|p| {
                at.get(&p.pid)
                    .map(|&i| self.processes.rows()[i])
                    .unwrap_or(Row {
                        pid: p.pid,
                        sequence_number: p.sequence_number,
                        ..Default::default()
                    })
            })
            .collect();

        let states: Arc<[ProcessState]> = self.time("states", |s| rows.iter().map(|row| s.state(row)).collect());

        let readable: ProcessMetrics = spec
            .processes
            .iter()
            .filter(|&m| self.sees_gui || !matches!(m, ProcessMetric::UserObjects | ProcessMetric::GdiObjects))
            .collect();
        let gui = readable.contains(ProcessMetric::UserObjects) || readable.contains(ProcessMetric::GdiObjects);
        let sources: Vec<Source> = self.time(if gui { "gui objects" } else { "sources" }, |s| {
            rows.iter()
                .map(|row| {
                    let (user_objects, gdi_objects) = match s.handles.get(row.pid) {
                        Some(handle) if gui => probes::gui_objects(handle),
                        _ => (0, 0),
                    };
                    let network = s.state.network(row.pid, row.sequence_number);
                    Source {
                        row: *row,
                        user_objects,
                        gdi_objects,
                        net_rx_bytes: network.recv_bytes,
                        net_tx_bytes: network.sent_bytes,
                    }
                })
                .collect()
        });
        let columns = Columns::build(readable, &sources);
        let machine = if spec.machine.is_empty() {
            MachineSample::default()
        } else {
            self.time("machine", |s| s.machine.sample(spec.machine, s.state.machine_totals()))
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
        Sampled {
            processes,
            states,
            sample: Arc::new(sample),
        }
    }

    fn state(&self, row: &Row) -> ProcessState {
        let handle = self.handles.get(row.pid);
        let power_throttling = handle.and_then(probes::power_throttling);
        let base_priority = ProcessPriority::from_base(row.base_priority);
        ProcessState {
            pid: row.pid,
            sequence_number: row.sequence_number,
            suspended: Some(row.suspended),
            efficiency_mode: power_throttling
                .zip(base_priority)
                .map(|(eco, base)| eco && base == ProcessPriority::Idle),
            base_priority,
            power_throttling,
            job_object_id: row.job_object_id,
            io_priority: handle.map_or(Default::default(), probes::io_priority),
        }
    }

    fn stop(&mut self) {
        if !self.running {
            return;
        }
        self.running = false;
        for provider in self.providers.iter().rev() {
            provider.stop();
        }
        if let Some(sink) = &self.sink {
            let dropped = sink.dropped();
            if dropped > 0 {
                tracing::warn!("events dropped by sink: {dropped}");
            }
        }
        self.router.take();
        self.sink.take();
        self.rx.take();
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::{MachineMetric, MachineMetrics, ProcessMetrics};

    fn config() -> SupervisorConfig {
        SupervisorConfig {
            session_namespace: Some("Uniproc-SupervisorTest-".into()),
            signature_store: "signatures-supervisor-test".into(),
        }
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_sample_covers_exactly_the_listed_processes() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new(Duration::from_millis(200));
        demand.set_wanted(Some(MetricSpec {
            interval: Duration::from_millis(200),
            processes: ProcessMetrics::all(),
            machine: MachineMetrics::all(),
        }));
        let mut supervisor = Supervisor::new(config(), demand);
        supervisor.start().expect("elevated");

        let first = supervisor.tick();
        std::thread::sleep(Duration::from_millis(250));
        let second = supervisor.tick();

        for report in [&first, &second] {
            let pids: Vec<u32> = report.processes.value.iter().map(|p| p.pid).collect();
            assert_eq!(*report.sample.pids, *pids);
            assert_eq!(report.states.len(), pids.len());
            assert_eq!(report.sample.columns.working_set.as_ref().unwrap().len(), pids.len());
        }
        assert_eq!(second.sample.snapshot, first.sample.snapshot + 1);
        assert!(second.sample.sampled_at > first.sample.sampled_at);

        let me = second.sample.pids.iter().position(|&pid| pid == std::process::id()).unwrap();
        let columns = &second.sample.columns;
        assert!(columns.cpu_user_time.as_ref().unwrap()[me] + columns.cpu_kernel_time.as_ref().unwrap()[me] > 0);
        assert!(columns.private_working_set.as_ref().unwrap()[me] > 0);
        assert!(columns.handles.as_ref().unwrap()[me] > 0);
        assert!(second.sample.machine.cpu.is_some() && second.sample.machine.memory.is_some());
        assert!(second.states[me].io_priority != crate::model::IoPriority::Unknown);
        assert!(second.costs.iter().any(|c| c.name == "snapshot"));
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_tick_before_the_sample_is_due_keeps_the_last_sample() {
        let _guard = crate::etw::router::tests::ETW_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let demand = Demand::new(Duration::from_secs(60));
        demand.set_wanted(Some(MetricSpec {
            interval: Duration::from_secs(60),
            processes: [ProcessMetric::Handles].into_iter().collect(),
            machine: [MachineMetric::Cpu].into_iter().collect(),
        }));
        let mut supervisor = Supervisor::new(config(), demand);
        supervisor.start().expect("elevated");
        let first = supervisor.tick();
        let again = supervisor.tick();
        assert!(Arc::ptr_eq(&first.sample, &again.sample));
        assert_eq!(first.sample.columns.working_set, None, "not asked for");
    }
}
