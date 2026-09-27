pub mod process;

use std::sync::Arc;
use std::time::Duration;

use futures::channel::oneshot;
use uniproc_agent_kit::{Busy, Runner};

use crate::api::{Command, CommandResult};
use crate::scm::{self, ScHandle, Scm, ServiceAction, Watching};

/// Win32 ERROR_BUSY: an operation on this target is already in flight.
const ERROR_BUSY: u32 = 170;

/// Threads commands run on; a service restart holds one for up to half a minute.
const WORKERS: usize = 4;

/// How long a service stays followed after a command on it went through,
/// so the snapshot shows it through its transition.
const FOLLOW_FOR: Duration = Duration::from_secs(60);

#[derive(Clone, PartialEq, Eq, Hash)]
enum Target {
    Process(u32),
    Service(String),
}

fn target(command: &Command) -> Target {
    match command {
        Command::Kill { pid }
        | Command::Suspend { pid }
        | Command::Resume { pid }
        | Command::SetPriority { pid, .. }
        | Command::SetAffinity { pid, .. } => Target::Process(*pid),
        Command::ServiceStart { name }
        | Command::ServiceStop { name }
        | Command::ServicePause { name }
        | Command::ServiceResume { name }
        | Command::ServiceRestart { name } => Target::Service(name.clone()),
    }
}

/// Where commands run: worker threads of its own, one command at a time
/// for any one process or service. Cheap to clone.
#[derive(Clone)]
pub struct Commands {
    runner: Runner<Target>,
    shared: Arc<Shared>,
}

struct Shared {
    scm: Scm,
    watching: Watching,
}

impl Commands {
    pub fn start(scm: Scm, watching: Watching) -> std::io::Result<Self> {
        Ok(Self {
            runner: Runner::start("command", WORKERS)?,
            shared: Arc::new(Shared { scm, watching }),
        })
    }

    /// Answers `ERROR_BUSY` at once while another command runs for the same
    /// process or service. The answer fails only if the command panicked.
    pub fn run(&self, command: Command) -> oneshot::Receiver<CommandResult> {
        let shared = self.shared.clone();
        match self.runner.run(target(&command), move || shared.execute(command)) {
            Ok(answer) => answer,
            Err(Busy) => {
                let (tx, rx) = oneshot::channel();
                let _ = tx.send(Err(ERROR_BUSY));
                rx
            }
        }
    }
}

impl Shared {
    fn execute(&self, command: Command) -> CommandResult {
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
            Command::ServiceRestart { name } => self.on_service(&name, |scm| scm::restart(scm, &name)),
        }
    }

    fn control(&self, name: &str, action: ServiceAction) -> CommandResult {
        self.on_service(name, |scm| scm::control(scm, name, action))
    }

    fn on_service(&self, name: &str, act: impl FnOnce(ScHandle) -> CommandResult) -> CommandResult {
        let hold = self.watching.hold(name, FOLLOW_FOR);
        let result = act(self.scm.connection()?.handle());
        if result.is_ok() {
            hold.keep();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scm::Watcher;

    fn commands() -> (Commands, Watcher) {
        let watcher = Watcher::start(Scm::new(), |_, _| {}).unwrap();
        (Commands::start(Scm::new(), watcher.watching()).unwrap(), watcher)
    }

    fn answer(rx: oneshot::Receiver<CommandResult>) -> CommandResult {
        futures::executor::block_on(rx).expect("answered")
    }

    #[test]
    #[ignore = "requires admin; restarts UNIPROC_TEST_SERVICE, the agent's own service by default"]
    fn a_restart_is_seen_through_every_state_by_a_watch_and_by_publish() {
        use crate::api::ServiceState;
        use futures::StreamExt;

        let name = std::env::var("UNIPROC_TEST_SERVICE")
            .unwrap_or_else(|_| crate::api::SERVICE_NAME.to_string());
        let (published, heard) = crossbeam_channel::unbounded();
        let watcher = Watcher::start(Scm::new(), move |_, status| {
            if let Some(status) = status {
                let _ = published.send(status.state);
            }
        })
        .unwrap();
        let commands = Commands::start(Scm::new(), watcher.watching()).unwrap();

        let mut watch = watcher.watching().watch(&name);
        let first = futures::executor::block_on(watch.next()).expect("the service exists");
        assert_eq!(first.state, ServiceState::Running, "{name} must be running to begin with");

        let restarted = commands.run(Command::ServiceRestart { name: name.clone() });
        let seen = std::thread::spawn(move || {
            let mut seen = vec![first];
            let deadline = std::time::Instant::now() + Duration::from_secs(240);
            while std::time::Instant::now() < deadline {
                let Some(status) = futures::executor::block_on(watch.next()) else { break };
                seen.push(status);
                let stopped = seen.iter().any(|s| s.state == ServiceState::Stopped);
                if stopped && status.state == ServiceState::Running {
                    break;
                }
            }
            seen
        })
        .join()
        .unwrap();
        assert_eq!(answer(restarted), Ok(()));

        let states: Vec<ServiceState> = seen.iter().map(|s| s.state).collect();
        eprintln!("{name}: {seen:#?}");
        let at = |state| states.iter().position(|&s| s == state);
        let (stopped, running) = (at(ServiceState::Stopped), states.iter().rposition(|&s| s == ServiceState::Running));
        assert!(stopped.is_some_and(|stopped| running.is_some_and(|running| stopped < running)), "{states:?}");
        assert!(states.contains(&ServiceState::StopPending), "{states:?}");
        assert_ne!(seen.last().unwrap().pid, first.pid, "a new process after the restart");

        let heard: Vec<ServiceState> = heard.try_iter().collect();
        assert!(heard.contains(&ServiceState::Stopped) && heard.last() == Some(&ServiceState::Running), "{heard:?}");
    }

    #[test]
    fn a_gone_process_cannot_be_killed() {
        let (commands, _watcher) = commands();
        let gone = commands.run(Command::Kill { pid: u32::MAX - 3 });
        assert!(answer(gone).is_err());
    }
}
