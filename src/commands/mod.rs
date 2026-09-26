pub mod process;

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::api::{Command, CommandResult};
use crate::scm::{self, Scm, ServiceAction};

/// Win32 ERROR_BUSY: an operation on this target is already in flight.
const ERROR_BUSY: u32 = 170;

/// Runs commands; knows which services a command is running for.
#[derive(Clone)]
pub struct Commands {
    scm: Scm,
    inflight: Arc<Mutex<HashSet<String>>>,
}

impl Commands {
    pub fn new(scm: Scm) -> Self {
        Self {
            scm,
            inflight: Arc::default(),
        }
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
                scm::restart(self.scm.connection()?.handle(), &name)
            }
        }
    }

    fn control(&self, name: &str, action: ServiceAction) -> CommandResult {
        let _guard = self.acquire(name)?;
        scm::control(self.scm.connection()?.handle(), name, action)
    }

    fn acquire(&self, name: &str) -> Result<InflightGuard, u32> {
        if !self.inflight.lock().insert(name.to_string()) {
            return Err(ERROR_BUSY);
        }
        Ok(InflightGuard {
            inflight: self.inflight.clone(),
            name: name.to_string(),
        })
    }
}

struct InflightGuard {
    inflight: Arc<Mutex<HashSet<String>>>,
    name: String,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inflight.lock().remove(&self.name);
    }
}
