pub mod process;
pub mod services;
mod vars;

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

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

#[derive(Clone)]
pub struct Commands {
    state: Rc<RefCell<CommandState>>,
}

struct CommandState {
    scm: Option<ScManager>,
    inflight: HashSet<String>,
}

impl Commands {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(CommandState {
                scm: None,
                inflight: HashSet::new(),
            })),
        }
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
        let _guard = self.acquire(&name)?;
        let scm = self.scm()?;
        spawn_blocking(move || services::restart(scm, &name)).await
    }

    async fn service(&self, name: String, action: ServiceAction) -> Outcome {
        let _guard = self.acquire(&name)?;
        let scm = self.scm()?;
        spawn_blocking(move || services::control(scm, &name, action)).await
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

    pub async fn process_set_priority(
        &self,
        pid: u32,
        priority: process::ProcessPriority,
    ) -> Outcome {
        spawn_blocking(move || process::set_priority(pid, priority)).await
    }

    pub async fn process_set_affinity(&self, pid: u32, mask: u64) -> Outcome {
        spawn_blocking(move || process::set_affinity(pid, mask)).await
    }

    fn scm(&self) -> Result<ScHandle, u32> {
        let mut state = self.state.borrow_mut();
        if let Some(scm) = &state.scm {
            return Ok(scm.handle());
        }
        let scm = ScManager::open()?;
        let handle = scm.handle();
        state.scm = Some(scm);
        Ok(handle)
    }

    fn acquire(&self, name: &str) -> Result<InflightGuard, u32> {
        {
            let mut state = self.state.borrow_mut();
            if !state.inflight.insert(name.to_string()) {
                return Err(ERROR_BUSY);
            }
        }
        Ok(InflightGuard {
            state: self.state.clone(),
            name: name.to_string(),
        })
    }
}

impl Default for Commands {
    fn default() -> Self {
        Self::new()
    }
}

struct InflightGuard {
    state: Rc<RefCell<CommandState>>,
    name: String,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.state.borrow_mut().inflight.remove(&self.name);
    }
}
