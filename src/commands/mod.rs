pub mod process;

use std::collections::HashSet;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Sender;
use futures::channel::oneshot;
use parking_lot::Mutex;

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

type Job = Box<dyn FnOnce() + Send>;

/// Where commands run: worker threads of its own, one command at a time
/// for any one process or service. Cheap to clone.
#[derive(Clone)]
pub struct Commands {
    shared: Arc<Shared>,
}

struct Shared {
    jobs: Sender<Job>,
    busy: Mutex<HashSet<Target>>,
    scm: Scm,
    watching: Watching,
}

impl Commands {
    pub fn start(scm: Scm, watching: Watching) -> std::io::Result<Self> {
        let (jobs, queue) = crossbeam_channel::unbounded::<Job>();
        for worker in 0..WORKERS {
            let queue = queue.clone();
            std::thread::Builder::new()
                .name(format!("command-{worker}"))
                .spawn(move || {
                    for job in queue {
                        let _ = std::panic::catch_unwind(AssertUnwindSafe(job));
                    }
                })?;
        }
        Ok(Self {
            shared: Arc::new(Shared {
                jobs,
                busy: Mutex::default(),
                scm,
                watching,
            }),
        })
    }

    /// Answers `ERROR_BUSY` at once while another command runs for the same
    /// process or service. The answer fails only if the command panicked.
    pub fn run(&self, command: Command) -> oneshot::Receiver<CommandResult> {
        self.submit(target(&command), move |shared| shared.execute(command))
    }

    fn submit(
        &self,
        target: Target,
        work: impl FnOnce(&Shared) -> CommandResult + Send + 'static,
    ) -> oneshot::Receiver<CommandResult> {
        let (tx, rx) = oneshot::channel();
        if !self.shared.busy.lock().insert(target.clone()) {
            let _ = tx.send(Err(ERROR_BUSY));
            return rx;
        }
        let shared = self.shared.clone();
        let job: Job = Box::new(move || {
            let free = Free {
                shared: shared.clone(),
                target,
            };
            let result = work(&shared);
            drop(free);
            let _ = tx.send(result);
        });
        let _ = self.shared.jobs.send(job);
        rx
    }
}

struct Free {
    shared: Arc<Shared>,
    target: Target,
}

impl Drop for Free {
    fn drop(&mut self) {
        self.shared.busy.lock().remove(&self.target);
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
    fn a_second_command_for_the_same_target_is_busy_until_the_first_is_done() {
        let (commands, _watcher) = commands();
        let (release, released) = crossbeam_channel::bounded::<()>(0);
        let first = commands.submit(Target::Process(1), move |_| {
            let _ = released.recv();
            Ok(())
        });

        let again = commands.submit(Target::Process(1), |_| Ok(()));
        assert_eq!(answer(again), Err(ERROR_BUSY));

        let other = commands.submit(Target::Process(2), |_| Ok(()));
        assert_eq!(answer(other), Ok(()), "another process is not held up");

        release.send(()).unwrap();
        assert_eq!(answer(first), Ok(()));
        let after = commands.submit(Target::Process(1), |_| Ok(()));
        assert_eq!(answer(after), Ok(()));
    }

    #[test]
    fn a_long_command_does_not_hold_up_the_rest() {
        let (commands, _watcher) = commands();
        let (release, released) = crossbeam_channel::bounded::<()>(0);
        let long = commands.submit(Target::Service("slow".into()), move |_| {
            let _ = released.recv();
            Ok(())
        });
        for pid in 0..(WORKERS as u32 * 2) {
            let quick = commands.submit(Target::Process(pid), |_| Ok(()));
            assert_eq!(answer(quick), Ok(()));
        }
        release.send(()).unwrap();
        assert_eq!(answer(long), Ok(()));
    }

    #[test]
    fn a_command_that_panics_frees_its_target_and_its_worker() {
        let (commands, _watcher) = commands();
        for _ in 0..(WORKERS * 2) {
            let panicked = commands.submit(Target::Process(7), |_| panic!("boom"));
            assert!(futures::executor::block_on(panicked).is_err());
        }
        let after = commands.submit(Target::Process(7), |_| Ok(()));
        assert_eq!(answer(after), Ok(()));
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
