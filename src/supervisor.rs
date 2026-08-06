use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::Receiver;
use dashmap::DashSet;
use parking_lot::Mutex;

use crate::etw::router::KernelRouter;
use crate::providers::provider::{LivePids, Provider};
use crate::settings::CollectorSettings;
use crate::sink::Sink;
use crate::state::SystemState;
use crate::state::events::StateChange;

pub struct SupervisorConfig {
    pub tick_interval: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(100),
        }
    }
}

pub struct Supervisor {
    providers: Vec<Box<dyn Provider>>,
    state: Arc<Mutex<SystemState>>,
    live_pids: LivePids,
    router: Option<KernelRouter>,
    sink: Option<Sink>,
    rx: Option<Receiver<StateChange>>,
    config: SupervisorConfig,
    settings: CollectorSettings,
    running: bool,
}

impl Supervisor {
    pub fn new(
        providers: Vec<Box<dyn Provider>>,
        config: SupervisorConfig,
        settings: CollectorSettings,
    ) -> Self {
        Self {
            providers,
            state: Arc::new(Mutex::new(SystemState::new())),
            live_pids: Arc::new(DashSet::new()),
            router: None,
            sink: None,
            rx: None,
            config,
            settings,
            running: false,
        }
    }

    pub fn state(&self) -> Arc<Mutex<SystemState>> {
        self.state.clone()
    }

    pub fn settings(&self) -> CollectorSettings {
        self.settings.clone()
    }

    pub fn tick_interval(&self) -> Duration {
        self.config.tick_interval
    }

    pub fn start(&mut self) -> Result<()> {
        let (sink, rx) = Sink::bounded(crate::sink::DEFAULT_CAPACITY);

        let mut builder = KernelRouter::builder();
        for p in &self.providers {
            p.register(&mut builder)?;
        }

        // `router` is a local: if any provider below fails, `?` drops it
        // right here, running `KernelRouter::Drop` (join pump, close
        // consumers, stop sessions) before the error propagates.
        let router = builder.start(sink.clone())?;

        for (started, p) in self.providers.iter().enumerate() {
            if let Err(e) = p.start(self.live_pids.clone(), sink.clone()) {
                // Providers before this one may have already spawned poller
                // threads; the router's own cleanup above doesn't reach them.
                for already_started in self.providers[..started].iter().rev() {
                    if !already_started.is_oneshot() {
                        already_started.stop();
                    }
                }
                return Err(e);
            }
        }

        for change in rx.try_iter() {
            self.apply(change);
        }

        self.router = Some(router);
        self.sink = Some(sink);
        self.rx = Some(rx);
        self.running = true;
        Ok(())
    }

    pub fn tick(&mut self) {
        let Some(rx) = self.rx.clone() else {
            return;
        };
        for change in rx.try_iter() {
            self.apply(change);
        }
    }

    pub fn stop(&mut self) {
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

    fn apply(&self, change: StateChange) {
        match &change {
            StateChange::ProcessStarted(e) | StateChange::ProcessRundown(e) => {
                self.live_pids.insert(e.pid);
            }
            StateChange::ProcessStopped(pid) => {
                self.live_pids.remove(pid);
            }
            _ => {}
        }
        self.state.lock().apply(change);
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop();
    }
}
