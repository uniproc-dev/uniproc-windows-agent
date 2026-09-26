use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Receiver;
use dashmap::DashMap;

use crate::etw::router::KernelRouter;
use crate::providers::provider::{LivePids, Provider};
use crate::report::Report;
use crate::settings::CollectorSettings;
use crate::sink::Sink;
use crate::state::SystemState;
use crate::state::events::StateChange;

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

/// Owns the machine's state; the providers feed it and every tick reports on it.
pub struct Supervisor {
    providers: Vec<Box<dyn Provider>>,
    state: SystemState,
    live_pids: LivePids,
    starts: u64,
    fresh_starts: bool,
    router: Option<KernelRouter>,
    sink: Option<Sink>,
    rx: Option<Receiver<StateChange>>,
    config: SupervisorConfig,
    settings: CollectorSettings,
    last: Option<Arc<Report>>,
    running: bool,
}

impl Supervisor {
    /// Nothing runs until [`start`](Self::start); `settings` stay live, the
    /// caller keeps a clone to change the intervals.
    pub fn new(config: SupervisorConfig, settings: CollectorSettings) -> Self {
        Self {
            providers: crate::providers::all(config.signature_store.clone(), &settings),
            state: SystemState::new(),
            live_pids: Arc::new(DashMap::new()),
            starts: 0,
            fresh_starts: false,
            router: None,
            sink: None,
            rx: None,
            config,
            settings,
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
            if let Err(e) = p.start(self.live_pids.clone(), sink.clone()) {
                for already_started in self.providers[..started].iter().rev() {
                    if !already_started.is_oneshot() {
                        already_started.stop();
                    }
                }
                return Err(e);
            }
        }

        self.drain_and_apply(&rx);

        self.router = Some(router);
        self.sink = Some(sink);
        self.rx = Some(rx);
        self.running = true;
        Ok(())
    }

    /// Applies what the providers sent since the last tick and reports the result.
    pub fn tick(&mut self) -> Arc<Report> {
        if let Some(rx) = self.rx.take() {
            self.drain_and_apply(&rx);
            self.rx = Some(rx);
        }
        let dropped = self.sink.as_ref().map_or(0, Sink::dropped);
        let sessions = self.router.as_ref().map_or_else(Vec::new, KernelRouter::health);
        let report = Arc::new(Report::build(&self.state, self.last.as_deref(), dropped, sessions));
        self.last = Some(report.clone());
        report
    }

    fn drain_and_apply(&mut self, rx: &Receiver<StateChange>) {
        for change in rx.try_iter() {
            self.apply(change);
        }
        if std::mem::take(&mut self.fresh_starts) {
            self.settings.memory_interval.wake();
        }
    }

    fn stop(&mut self) {
        if !self.running {
            return;
        }
        self.running = false;
        for provider in self.providers.iter().rev() {
            if !provider.is_oneshot() {
                provider.stop();
            }
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

    fn apply(&mut self, change: StateChange) {
        match &change {
            StateChange::ProcessStarted(e) => {
                self.starts += 1;
                self.live_pids.insert(e.pid, self.starts);
                self.fresh_starts = true;
            }
            StateChange::ProcessRundown(e) => {
                self.starts += 1;
                self.live_pids.insert(e.pid, self.starts);
            }
            StateChange::ProcessStopped(pid) => {
                self.live_pids.remove(pid);
            }
            _ => {}
        }
        self.state.apply(change);
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop();
    }
}
