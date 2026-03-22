pub mod provider;
pub mod settings;
pub mod state;

use std::sync::Arc;
use std::time::Duration;

use crate::collector::provider::{ProcessMap, Provider};
use crate::collector::settings::CollectorSettings;
use crate::collector::state::{ProcessEntry, ProcessTable, StateChange};
use crate::etw::kernel_session::KernelSessionRouter;
use anyhow::Result;
use dashmap::DashMap;
use windows::Win32::System::Diagnostics::Etw::*;

pub struct CollectorConfig {
    pub tick_interval: Duration,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(100),
        }
    }
}

pub struct ProcessStatsCollector {
    providers: Vec<Box<dyn Provider>>,
    state: ProcessTable,
    processes: ProcessMap,
    kernel_session: Option<Arc<KernelSessionRouter>>,
    config: CollectorConfig,
    settings: CollectorSettings,
    running: bool,
}

impl ProcessStatsCollector {
    pub fn new(
        providers: Vec<Box<dyn Provider>>,
        config: CollectorConfig,
        settings: CollectorSettings,
    ) -> Self {
        Self {
            providers,
            state: ProcessTable::new(),
            processes: Arc::new(DashMap::new()),
            kernel_session: None,
            config,
            settings,
            running: false,
        }
    }

    pub fn settings(&self) -> CollectorSettings {
        self.settings.clone()
    }

    pub fn start(&mut self) -> Result<()> {
        let kernel = KernelSessionRouter::start(
            EVENT_TRACE_FLAG_PROCESS.0
                | EVENT_TRACE_FLAG_THREAD.0
                | EVENT_TRACE_FLAG_DISK_IO.0
                | EVENT_TRACE_FLAG_NETWORK_TCPIP.0,
        )?;

        for i in 0..self.providers.len() {
            self.providers[i].start(self.processes.clone(), kernel.clone())?;

            if self.providers[i].is_oneshot() {
                for change in self.providers[i].drain() {
                    self.apply(change);
                }
                self.providers[i].stop();
            }
        }

        self.kernel_session = Some(kernel);
        self.running = true;
        Ok(())
    }

    pub fn tick(&mut self) {
        for i in 0..self.providers.len() {
            if self.providers[i].is_oneshot() {
                continue;
            }
            for change in self.providers[i].drain() {
                self.apply(change);
            }
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
        self.kernel_session.take();
    }

    fn apply(&mut self, change: StateChange) {
        match &change {
            StateChange::ProcessStarted(e) | StateChange::ProcessRundown(e) => {
                self.processes.insert(e.pid, ProcessEntry::from(e));
            }
            StateChange::ProcessStopped(pid) => {
                self.processes.remove(pid);
            }
            _ => {}
        }
        self.state.apply(change);
    }

    pub fn processes(&self) -> Vec<ProcessEntry> {
        self.state.snapshot().into_iter().cloned().collect()
    }

    pub fn get_process(&self, pid: u32) -> Option<ProcessEntry> {
        self.state.get(pid).cloned()
    }
}

impl Drop for ProcessStatsCollector {
    fn drop(&mut self) {
        self.stop();
    }
}
