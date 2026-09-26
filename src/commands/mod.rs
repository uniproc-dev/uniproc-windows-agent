pub mod cpu;
pub mod process;
pub mod services;
mod vars;

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::api::ProcessPriority;
use crate::commands::services::{ScHandle, ScManager, ServiceAction};
use crate::commands::vars::ERROR_BUSY;

pub type Outcome = Result<(), u32>;

/// Awaitable wrapper over compio's spawn_blocking: resumes a panic in the
/// blocking closure instead of swallowing it into the return type.
async fn spawn_blocking(f: impl FnOnce() -> Outcome + Send + 'static) -> Outcome {
    compio::runtime::spawn_blocking(f)
        .await
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

#[derive(Clone, Default)]
pub struct Commands {
    state: Arc<Mutex<CommandState>>,
}

#[derive(Default)]
struct CommandState {
    scm: Option<ScManager>,
    inflight: HashSet<String>,
}

impl Commands {
    pub fn new() -> Self {
        Self::default()
    }

    /// Blocks until the SCM has taken the control; `ERROR_BUSY` while another one runs for the same service.
    pub fn control_service(&self, name: &str, action: ServiceAction) -> Outcome {
        let _guard = self.acquire(name)?;
        services::control(self.scm()?, name, action)
    }

    /// Blocks until the service has stopped and been started again.
    pub fn restart_service(&self, name: &str) -> Outcome {
        let _guard = self.acquire(name)?;
        services::restart(self.scm()?, name)
    }

    pub async fn service_start(&self, name: String) -> Outcome {
        self.service(name, ServiceAction::Start).await
    }

    pub async fn service_stop(&self, name: String) -> Outcome {
        self.service(name, ServiceAction::Stop).await
    }

    pub async fn service_pause(&self, name: String) -> Outcome {
        self.service(name, ServiceAction::Pause).await
    }

    pub async fn service_resume(&self, name: String) -> Outcome {
        self.service(name, ServiceAction::Resume).await
    }

    pub async fn service_restart(&self, name: String) -> Outcome {
        let this = self.clone();
        spawn_blocking(move || this.restart_service(&name)).await
    }

    async fn service(&self, name: String, action: ServiceAction) -> Outcome {
        let this = self.clone();
        spawn_blocking(move || this.control_service(&name, action)).await
    }

    pub async fn process_kill(&self, pid: u32) -> Outcome {
        spawn_blocking(move || process::kill(pid)).await
    }

    pub async fn process_suspend(&self, pid: u32) -> Outcome {
        spawn_blocking(move || process::suspend(pid)).await
    }

    pub async fn process_resume(&self, pid: u32) -> Outcome {
        spawn_blocking(move || process::resume(pid)).await
    }

    pub async fn process_set_priority(&self, pid: u32, priority: ProcessPriority) -> Outcome {
        spawn_blocking(move || process::set_priority(pid, priority)).await
    }

    pub async fn process_set_affinity(&self, pid: u32, mask: u64) -> Outcome {
        spawn_blocking(move || process::set_affinity(pid, mask)).await
    }

    fn scm(&self) -> Result<ScHandle, u32> {
        let mut state = self.state.lock();
        if let Some(scm) = &state.scm {
            return Ok(scm.handle());
        }
        let scm = ScManager::open()?;
        let handle = scm.handle();
        state.scm = Some(scm);
        Ok(handle)
    }

    fn acquire(&self, name: &str) -> Result<InflightGuard, u32> {
        if !self.state.lock().inflight.insert(name.to_string()) {
            return Err(ERROR_BUSY);
        }
        Ok(InflightGuard {
            state: self.state.clone(),
            name: name.to_string(),
        })
    }
}

struct InflightGuard {
    state: Arc<Mutex<CommandState>>,
    name: String,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.state.lock().inflight.remove(&self.name);
    }
}
