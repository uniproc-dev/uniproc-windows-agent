//! Process starts and exits as they happen, from ETW: Kernel-Process for the
//! instance and the totals at exit, the kernel's own Process event for the
//! command line and the user, and the Task Scheduler for the task that
//! started one. The recent ones are held for watchers that come later.

mod assemble;
mod decode;
mod history;
mod resolve;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use parking_lot::Mutex;
use smol_str::SmolStr;
use uniproc_agent_kit::Notify;
use crate::bindings::{EVENT_TRACE_FLAG_PROCESS, TRACE_LEVEL_INFORMATION};

use crate::etw::router::{EVERY_KEYWORD, Enable, KernelRouterBuilder};
use crate::providers::provider::Provider;
use crate::report::SessionHealth;
use assemble::{Assembler, SECOND};
use decode::{KERNEL_PROCESS, KERNEL_PROCESS_KEYWORD, PROCESS, TASK_SCHEDULER};
use uniproc_etw::OwnedEvent;
use history::{Cursor, History};
use resolve::Machine;

/// How long events are held for watchers that come later.
const KEPT_FOR: u64 = 3600 * SECOND;
/// The most memory the held events take.
const KEPT_BYTES: usize = 4 << 20;
/// The most one batch carries, well under a reader's traversal limit.
const BATCH_BYTES: usize = 1 << 20;
/// How often what waited too long is let out while nothing comes.
const TICK: Duration = Duration::from_millis(250);
/// Events copied out of ETW and not read yet, at most.
const QUEUED: usize = 1 << 14;

static PROVIDERS: [windows_core::GUID; 3] = [KERNEL_PROCESS, PROCESS, TASK_SCHEDULER];

/// The process events as they come and the recent ones held; cheap to clone.
#[derive(Clone)]
pub struct ProcessEvents {
    shared: Arc<Shared>,
}

struct Shared {
    history: Mutex<History>,
    told: Notify,
    closed: AtomicBool,
}

impl ProcessEvents {
    /// Starts the thread that reads the events. `services` names the
    /// services a process hosts; `images` the Win32 image path of a listed
    /// process by pid and sequence number, empty when none is listed. The
    /// provider feeds the thread from the ETW sessions it registers; the
    /// thread ends once the provider and every router it registered with are
    /// gone.
    pub fn start(
        services: impl FnMut(u32) -> Vec<SmolStr> + Send + 'static,
        images: impl FnMut(u32, u64) -> SmolStr + Send + 'static,
    ) -> Result<(Self, ProcessEventsProvider)> {
        let events = Self::new(now());
        let (input, inbox) = crossbeam_channel::bounded(QUEUED);
        let dropped = Arc::new(AtomicU64::new(0));
        std::thread::Builder::new().name("process-events".into()).spawn({
            let shared = events.shared.clone();
            let dropped = dropped.clone();
            let machine = Machine::new(services, images);
            move || run(inbox, shared, dropped, machine)
        })?;
        Ok((events, ProcessEventsProvider { input, dropped }))
    }

    fn new(started_at: u64) -> Self {
        Self {
            shared: Arc::new(Shared {
                history: Mutex::new(History::new(started_at, KEPT_FOR, KEPT_BYTES)),
                told: Notify::new(),
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Everything held, then each event as it comes.
    pub fn watch(&self) -> ProcessEventsWatch {
        ProcessEventsWatch {
            shared: self.shared.clone(),
            cursor: Cursor::default(),
        }
    }
}

/// One watcher's place in the events.
pub struct ProcessEventsWatch {
    shared: Arc<Shared>,
    cursor: Cursor,
}

impl ProcessEventsWatch {
    /// The next batch: first what is held, then what comes. `None` once the
    /// events stopped and everything was read.
    pub async fn next(&mut self) -> Option<ProcessEventBatch> {
        loop {
            let generation = self.shared.told.generation();
            let closed = self.shared.closed.load(Ordering::SeqCst);
            if let Some(batch) = self.try_next() {
                return Some(batch);
            }
            if closed {
                return None;
            }
            self.shared.told.changed(generation).await;
        }
    }

    /// The next batch if one is ready.
    pub fn try_next(&mut self) -> Option<ProcessEventBatch> {
        self.shared.history.lock().read(&mut self.cursor, BATCH_BYTES)
    }
}

/// Feeds [`ProcessEvents`] from the ETW sessions it registers.
pub struct ProcessEventsProvider {
    input: Sender<Input>,
    dropped: Arc<AtomicU64>,
}

enum Input {
    Record(OwnedEvent),
    KernelLost(u64),
}

impl Provider for ProcessEventsProvider {
    fn register(&self, builder: &mut KernelRouterBuilder) -> Result<()> {
        let input = self.input.clone();
        let dropped = self.dropped.clone();
        builder
            .kernel_flags(EVENT_TRACE_FLAG_PROCESS)
            .manifest(
                KERNEL_PROCESS,
                Enable {
                    keywords: KERNEL_PROCESS_KEYWORD,
                    level: TRACE_LEVEL_INFORMATION as u8,
                },
            )
            .manifest(TASK_SCHEDULER, EVERY_KEYWORD)
            .on(&PROVIDERS, move |event| {
                if decode::wanted(event) && input.try_send(Input::Record(event.to_owned())).is_err() {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
                None
            });
        Ok(())
    }

    fn health(&self, sessions: &[SessionHealth]) {
        let name = format!("{KERNEL_PROCESS:?}").replace(['{', '}'], "");
        if let Some(session) = sessions.iter().find(|s| s.name.ends_with(&name)) {
            let _ = self.input.try_send(Input::KernelLost(session.events_lost as u64));
        }
    }

    fn stop(&self) {}
}

fn run(inbox: Receiver<Input>, shared: Arc<Shared>, dropped: Arc<AtomicU64>, mut machine: Machine) {
    let mut assembler = Assembler::default();
    let (mut kernel_lost, mut dropped_seen, mut lost) = (0u64, 0u64, 0u64);
    let mut take = |input: Input, assembler: &mut Assembler, lost: &mut u64| match input {
        Input::Record(record) => {
            if let Some(raw) = decode::decode(&record.event(), resolve::working_directory) {
                assembler.add(raw);
            }
        }
        Input::KernelLost(total) => {
            *lost += total.checked_sub(kernel_lost).unwrap_or(total);
            kernel_lost = total;
        }
    };
    loop {
        match inbox.recv_timeout(TICK) {
            Ok(input) => {
                take(input, &mut assembler, &mut lost);
                while let Ok(input) = inbox.try_recv() {
                    take(input, &mut assembler, &mut lost);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let dropped_now = dropped.load(Ordering::Relaxed);
        lost += dropped_now - dropped_seen;
        dropped_seen = dropped_now;
        let now = now();
        release(&mut assembler, &mut machine, &shared, now, now, std::mem::take(&mut lost));
    }
    release(&mut assembler, &mut machine, &shared, u64::MAX, now(), lost);
    shared.closed.store(true, Ordering::SeqCst);
    shared.told.notify();
}

/// Lets out what is ready at `ready_at` and holds it as of `now`.
fn release(assembler: &mut Assembler, machine: &mut Machine, shared: &Shared, ready_at: u64, now: u64, lost: u64) {
    let events = assembler.release(ready_at, machine);
    if events.is_empty() && lost == 0 {
        return;
    }
    let mut history = shared.history.lock();
    history.kernel_lost(u32::try_from(lost).unwrap_or(u32::MAX));
    for mut event in events {
        if let ProcessEventKind::Exited(exited) = &mut event.kind {
            exited.image_path = history
                .image_of(event.pid, event.sequence_number)
                .unwrap_or_else(|| machine.listed_image(event.pid, event.sequence_number));
        }
        history.push(event, now);
    }
    drop(history);
    shared.told.notify();
}

/// System time now as a FILETIME.
fn now() -> u64 {
    let now = unsafe { crate::bindings::GetSystemTimePreciseAsFileTime() };
    ((now.dwHighDateTime as u64) << 32) | now.dwLowDateTime as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use std::time::Instant;

    const T: u64 = 134_000_000_000_000_000;

    fn exit(pid: u32, time: u64, exit_code: u32) -> ProcessEvent {
        ProcessEvent {
            pid,
            sequence_number: pid as u64 * 10,
            time,
            kind: ProcessEventKind::Exited(ProcessExited {
                exit_code,
                ..Default::default()
            }),
        }
    }

    fn pids(batch: &ProcessEventBatch) -> Vec<u32> {
        batch.events.iter().map(|e| e.pid).collect()
    }

    fn tell(events: &ProcessEvents, event: ProcessEvent) {
        let time = event.time;
        events.shared.history.lock().push(event, time);
        events.shared.told.notify();
    }

    #[test]
    fn a_watch_reads_what_is_held_then_waits_for_what_comes_and_ends_with_the_events() {
        let events = ProcessEvents::new(T);
        tell(&events, exit(1, T + 1, 0));
        let mut watch = events.watch();
        let first = block_on(watch.next());
        assert_eq!(first.as_ref().map(|b| (b.history_from, pids(b))), Some((T, vec![1])));
        assert!(watch.try_next().is_none());

        let waiting = std::thread::spawn(move || {
            let next = block_on(watch.next()).map(|b| pids(&b));
            (next, block_on(watch.next()).map(|b| pids(&b)))
        });
        std::thread::sleep(Duration::from_millis(50));
        tell(&events, exit(2, T + 2, 0));
        std::thread::sleep(Duration::from_millis(50));
        events.shared.closed.store(true, Ordering::SeqCst);
        events.shared.told.notify();
        assert_eq!(waiting.join().unwrap(), (Some(vec![2]), None));
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_child_s_start_and_exit_come_with_its_command_line_and_exit_code() {
        use crate::etw::router::KernelRouter;
        use crate::sink::Sink;

        let (events, provider) = ProcessEvents::start(|_| vec!["Parent".into()], |_, _| SmolStr::default()).unwrap();
        let mut watch = events.watch();
        let (sink, _changes) = Sink::bounded(1 << 16, || {});
        let mut builder = KernelRouter::builder();
        builder.session_namespace("Uniproc-ProcessEventsTest-");
        provider.register(&mut builder).unwrap();
        let router = builder.start(sink).expect("router start");
        router.set_flush_timer(50).unwrap();
        std::thread::sleep(Duration::from_millis(500));

        let mut child = std::process::Command::new("cmd")
            .args(["/d", "/c", "exit 7"])
            .current_dir(std::env::temp_dir())
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let exited_at = Instant::now();

        let mut told = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && told.iter().filter(|e: &&Arc<ProcessEvent>| e.pid == pid).count() < 2 {
            while let Some(batch) = watch.try_next() {
                told.extend(batch.events);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let took = exited_at.elapsed();
        drop(router);
        drop(provider);

        let mine: Vec<&ProcessEvent> = told.iter().filter(|e| e.pid == pid).map(|e| &**e).collect();
        let started = mine.iter().find_map(|e| match &e.kind {
            ProcessEventKind::Started(started) => Some(started),
            ProcessEventKind::Exited(_) => None,
        });
        let exited = mine.iter().find_map(|e| match &e.kind {
            ProcessEventKind::Exited(exited) => Some(exited.clone()),
            ProcessEventKind::Started(_) => None,
        });
        let me = unsafe { crate::providers::utils::query_sequence_number(crate::bindings::GetCurrentProcess()) };
        let started = started.unwrap_or_else(|| panic!("no start of {pid} among {} events", told.len()));
        assert_eq!((started.parent_pid, Some(started.parent_sequence_number)), (std::process::id(), me));
        assert!(started.command_line.contains("exit 7"), "{started:?}");
        assert!(started.image_path.to_lowercase().ends_with(r"\cmd.exe") && started.image_path.get(1..2) == Some(":"), "{started:?}");
        assert!(started.user.contains('\\'), "{started:?}");
        assert_eq!(started.parent_services, ["Parent"]);
        let exited = exited.unwrap_or_else(|| panic!("no exit of {pid} among {mine:?}"));
        assert_eq!(exited.exit_code, 7, "{mine:?}");
        assert!(exited.cpu_cycles > 0 && exited.peak_commit > 0, "{mine:?}");
        assert_eq!(exited.image_name.to_lowercase(), "cmd.exe", "{exited:?}");
        assert_eq!(exited.image_path, started.image_path, "{exited:?}");
        assert_eq!(exited.start_time, mine[0].time, "{mine:?}");
        assert!(mine[0].sequence_number != 0 && mine.iter().all(|e| e.sequence_number == mine[0].sequence_number));
        let bound = Duration::from_nanos(assemble::WAITS_AT_MOST * 100);
        assert!(took < bound, "told {took:?} after the exit: it waited for the bound, not for its halves");
    }
}

/// A process started or exited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessEvent {
    pub pid: u32,
    pub sequence_number: u64,
    /// FILETIME of the start or the exit.
    pub time: u64,
    pub kind: ProcessEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessEventKind {
    Started(ProcessStarted),
    Exited(ProcessExited),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessStarted {
    pub parent_pid: u32,
    /// 0 when not known.
    pub parent_sequence_number: u64,
    pub session_id: u32,
    /// Win32 path; the NT path when no drive letter maps to it.
    pub image_path: SmolStr,
    /// As the process was created, unparsed; empty when the kernel's event
    /// did not come.
    pub command_line: SmolStr,
    /// DOMAIN\name of the token's user; the SID string when it does not resolve.
    pub user: SmolStr,
    pub elevated: Option<bool>,
    pub package_full_name: SmolStr,
    /// Empty when the process exited before it was read or could not be read.
    pub working_directory: SmolStr,
    /// Path of the Task Scheduler task that started it; empty otherwise.
    pub scheduled_task: SmolStr,
    /// Services hosted by the parent when the process started.
    pub parent_services: Vec<SmolStr>,
}

/// Who exited, and the totals over its whole life as the kernel reports them at exit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessExited {
    /// Win32 path, from the start held or the process list; empty when the
    /// agent never knew the process whole.
    pub image_path: SmolStr,
    /// The kernel's own name for the image, cut to its first 14 characters.
    pub image_name: SmolStr,
    /// FILETIME of the creation; 0 when unknown.
    pub start_time: u64,
    pub exit_code: u32,
    pub cpu_cycles: u64,
    pub io_read_ops: u64,
    pub io_write_ops: u64,
    /// In steps of 1024: the kernel counts KiB.
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub peak_commit: u64,
    pub handles: u32,
    pub hard_faults: u32,
}

/// What one call to a watcher carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessEventBatch {
    /// In the first batch only, 0 after it: the FILETIME from which on
    /// nothing is missing.
    pub history_from: u64,
    /// In order of time within the batch; a start always before its exit,
    /// but a later batch may carry an earlier event.
    pub events: Vec<Arc<ProcessEvent>>,
    /// Events missing since the previous batch: dropped by the kernel, or
    /// gone from the hold before this watcher was sent them.
    pub lost: u32,
}
