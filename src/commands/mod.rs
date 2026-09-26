pub mod process;
pub mod services;
mod vars;

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::api::{Command, CommandResult};
use crate::commands::services::{ScHandle, ScManager, ServiceAction};
use crate::commands::vars::ERROR_BUSY;

/// Runs commands; holds the SCM connection and the services a command is running for.
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

    /// Blocks until done; `ERROR_BUSY` while another command runs for the same service.
    pub fn run(&self, command: Command) -> CommandResult {
        match command {
            Command::Kill { pid } => process::kill(pid),
            Command::Suspend { pid } => process::suspend(pid),
            Command::Resume { pid } => process::resume(pid),
            Command::SetPriority { pid, priority } => process::set_priority(pid, priority),
            Command::SetAffinity { pid, mask } => process::set_affinity(pid, mask),
            Command::ServiceStart { name } => self.control(&name, ServiceAction::Start),
            Command::ServiceStop { name } => self.control(&name, ServiceAction::Stop),
            Command::ServicePause { name } => self.control(&name, ServiceAction::Pause),
            Command::ServiceResume { name } => self.control(&name, ServiceAction::Resume),
            Command::ServiceRestart { name } => {
                let _guard = self.acquire(&name)?;
                services::restart(self.scm()?, &name)
            }
        }
    }

    fn control(&self, name: &str, action: ServiceAction) -> CommandResult {
        let _guard = self.acquire(name)?;
        services::control(self.scm()?, name, action)
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
