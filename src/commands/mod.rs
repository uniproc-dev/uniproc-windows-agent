#[cfg(feature = "service")]
pub mod cpu;
pub mod process;
pub mod services;
mod vars;

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::commands::services::{ScHandle, ScManager, ServiceAction};
use crate::commands::vars::ERROR_BUSY;

pub type Outcome = Result<(), u32>;

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
