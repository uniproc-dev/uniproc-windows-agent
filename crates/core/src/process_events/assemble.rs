//! Puts a start together from the events that tell it in different sessions,
//! and lets the events out in order of time once every half had time to come.

use smol_str::SmolStr;

use super::{ProcessEvent, ProcessEventKind, ProcessExited, ProcessStarted};

/// FILETIME ticks in a second.
pub(crate) const SECOND: u64 = 10_000_000;

/// How far apart in time the halves of one start may be.
const PAIRED_WITHIN: u64 = SECOND;

/// How long an event waits for what is told in other sessions: longer than
/// the slowest flush timer.
pub(crate) const WAITS_AT_MOST: u64 = SECOND + SECOND / 4;

/// Kernel-Process's start: the instance and its parent.
#[derive(Clone, Debug, Default)]
pub(crate) struct Created {
    pub pid: u32,
    pub sequence_number: u64,
    pub time: u64,
    pub parent_pid: u32,
    pub parent_sequence_number: u64,
    pub session_id: u32,
    /// NT path.
    pub image: SmolStr,
    pub elevated: Option<bool>,
    pub package_full_name: SmolStr,
    pub working_directory: SmolStr,
}

/// The kernel's own Process start: the command line and the user.
#[derive(Clone, Debug, Default)]
pub(crate) struct Launched {
    pub pid: u32,
    pub time: u64,
    pub sid: Vec<u8>,
    pub command_line: SmolStr,
}

/// The Task Scheduler created this process for a task.
#[derive(Clone, Debug, Default)]
pub(crate) struct Scheduled {
    pub pid: u32,
    pub time: u64,
    pub task: SmolStr,
}

/// Kernel-Process's exit.
#[derive(Clone, Debug, Default)]
pub(crate) struct Ended {
    pub pid: u32,
    pub sequence_number: u64,
    pub time: u64,
    pub exited: ProcessExited,
}

pub(crate) enum Raw {
    Created(Created),
    Launched(Launched),
    Scheduled(Scheduled),
    Ended(Ended),
}

/// What a start needs from the machine as it goes out.
pub(crate) trait Resolve {
    fn image_path(&mut self, nt: &str) -> SmolStr;
    fn user(&mut self, sid: &[u8]) -> SmolStr;
    fn parent_services(&mut self, pid: u32) -> Vec<SmolStr>;
}

#[derive(Default)]
pub(crate) struct Assembler {
    pending: Vec<Pending>,
    launched: Vec<Launched>,
    scheduled: Vec<Scheduled>,
    /// The starts let out lately, as pid, sequence number and creation time.
    went: Vec<(u32, u64, u64)>,
}

enum Pending {
    Start {
        created: Created,
        launched: Option<Launched>,
        task: SmolStr,
        services: Option<Vec<SmolStr>>,
    },
    Exit(Ended),
}

impl Pending {
    fn order(&self) -> (u64, u8) {
        match self {
            Self::Start { created, .. } => (created.time, 0),
            Self::Exit(ended) => (ended.time, 1),
        }
    }

    fn into_event(self, resolve: &mut impl Resolve) -> ProcessEvent {
        match self {
            Self::Start {
                created,
                launched,
                task,
                services,
            } => ProcessEvent {
                pid: created.pid,
                sequence_number: created.sequence_number,
                time: created.time,
                kind: ProcessEventKind::Started(ProcessStarted {
                    parent_pid: created.parent_pid,
                    parent_sequence_number: created.parent_sequence_number,
                    session_id: created.session_id,
                    image_path: resolve.image_path(&created.image),
                    user: launched.as_ref().map(|l| resolve.user(&l.sid)).unwrap_or_default(),
                    command_line: launched.map(|l| l.command_line).unwrap_or_default(),
                    elevated: created.elevated,
                    package_full_name: created.package_full_name,
                    working_directory: created.working_directory,
                    scheduled_task: task,
                    parent_services: services.unwrap_or_else(|| resolve.parent_services(created.parent_pid)),
                }),
            },
            Self::Exit(ended) => ProcessEvent {
                pid: ended.pid,
                sequence_number: ended.sequence_number,
                time: ended.time,
                kind: ProcessEventKind::Exited(ended.exited),
            },
        }
    }
}

trait Half {
    fn pid(&self) -> u32;
    fn time(&self) -> u64;
}

impl Half for Launched {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn time(&self) -> u64 {
        self.time
    }
}

impl Half for Scheduled {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn time(&self) -> u64 {
        self.time
    }
}

fn near(a: u64, b: u64) -> bool {
    a.abs_diff(b) <= PAIRED_WITHIN
}

/// The half of `pid`'s start nearest to `time`, taken out of `halves`.
fn take_nearest<H: Half>(halves: &mut Vec<H>, pid: u32, time: u64) -> Option<H> {
    let index = halves
        .iter()
        .enumerate()
        .filter(|(_, half)| half.pid() == pid && near(half.time(), time))
        .min_by_key(|(_, half)| half.time().abs_diff(time))
        .map(|(index, _)| index)?;
    Some(halves.swap_remove(index))
}

impl Assembler {
    pub fn add(&mut self, raw: Raw) {
        match raw {
            Raw::Created(created) => {
                let launched = take_nearest(&mut self.launched, created.pid, created.time);
                let task = take_nearest(&mut self.scheduled, created.pid, created.time).map(|s| s.task);
                self.pending.push(Pending::Start {
                    created,
                    launched,
                    task: task.unwrap_or_default(),
                    services: None,
                });
            }
            Raw::Launched(half) => {
                if let Some(slot) = self.nearest_start(half.pid, half.time, |launched, _| launched.is_none()) {
                    *slot.0 = Some(half);
                } else {
                    self.launched.push(half);
                }
            }
            Raw::Scheduled(half) => {
                if let Some(slot) = self.nearest_start(half.pid, half.time, |_, task| task.is_empty()) {
                    *slot.1 = half.task;
                } else {
                    self.scheduled.push(half);
                }
            }
            Raw::Ended(ended) => self.pending.push(Pending::Exit(ended)),
        }
    }

    /// The pending start of `pid` nearest to `time` that `open` accepts.
    fn nearest_start(
        &mut self,
        pid: u32,
        time: u64,
        open: impl Fn(&Option<Launched>, &SmolStr) -> bool,
    ) -> Option<(&mut Option<Launched>, &mut SmolStr)> {
        self.pending
            .iter_mut()
            .filter_map(|pending| match pending {
                Pending::Start {
                    created, launched, task, ..
                } if created.pid == pid && near(created.time, time) && open(launched, task) =>
                {
                    Some((created.time.abs_diff(time), launched, task))
                }
                _ => None,
            })
            .min_by_key(|(distance, _, _)| *distance)
            .map(|(_, launched, task)| (launched, task))
    }

    /// The events ready at `now`, in order of time. A start is ready once its
    /// command line joined, and its task too when the Task Scheduler is its
    /// parent; an exit once its start went out. What waited
    /// [`WAITS_AT_MOST`] goes out with whatever of its halves came by then.
    pub fn release(&mut self, now: u64, resolve: &mut impl Resolve) -> Vec<ProcessEvent> {
        let waited = |time: u64| time.saturating_add(WAITS_AT_MOST) <= now;
        self.pending.sort_by_key(Pending::order);
        let mut held = Vec::new();
        let mut events = Vec::new();
        for mut pending in std::mem::take(&mut self.pending) {
            let due = match &mut pending {
                Pending::Start {
                    created,
                    launched,
                    task,
                    services,
                } => {
                    let mut scheduler = || {
                        services
                            .get_or_insert_with(|| resolve.parent_services(created.parent_pid))
                            .iter()
                            .any(|name| name == "Schedule")
                    };
                    let due = waited(created.time) || launched.is_some() && (!task.is_empty() || !scheduler());
                    if due {
                        self.went.push((created.pid, created.sequence_number, created.time));
                    } else {
                        held.push((created.pid, created.sequence_number));
                    }
                    due
                }
                Pending::Exit(ended) => {
                    let instance = (ended.pid, ended.sequence_number);
                    !held.contains(&instance)
                        && (waited(ended.exited.start_time) || self.went.iter().any(|&(pid, n, _)| (pid, n) == instance))
                }
            };
            if due {
                events.push(pending.into_event(resolve));
            } else {
                self.pending.push(pending);
            }
        }
        self.went.retain(|&(_, _, created)| !waited(created));
        let open = |half: &dyn Half| half.time() + PAIRED_WITHIN + WAITS_AT_MOST > now;
        self.launched.retain(|half| open(half));
        self.scheduled.retain(|half| open(half));
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 134_000_000_000_000_000;
    const MS: u64 = SECOND / 1000;

    struct Machine;

    impl Resolve for Machine {
        fn image_path(&mut self, nt: &str) -> SmolStr {
            nt.replace(r"\Device\HarddiskVolume3", "C:").into()
        }

        fn user(&mut self, sid: &[u8]) -> SmolStr {
            match sid {
                [] => SmolStr::default(),
                _ => r"HOST\me".into(),
            }
        }

        fn parent_services(&mut self, pid: u32) -> Vec<SmolStr> {
            match pid {
                600 => vec!["Dnscache".into()],
                700 => vec!["Schedule".into()],
                _ => Vec::new(),
            }
        }
    }

    fn created_by(pid: u32, sequence_number: u64, time: u64) -> Created {
        Created {
            pid,
            sequence_number,
            time,
            parent_pid: 600,
            parent_sequence_number: 60,
            session_id: 1,
            image: r"\Device\HarddiskVolume3\Windows\System32\cmd.exe".into(),
            elevated: Some(false),
            ..Default::default()
        }
    }

    fn created(pid: u32, sequence_number: u64, time: u64) -> Raw {
        Raw::Created(created_by(pid, sequence_number, time))
    }

    fn ended_since(pid: u32, sequence_number: u64, created: u64, time: u64, exit_code: u32) -> Raw {
        Raw::Ended(Ended {
            pid,
            sequence_number,
            time,
            exited: ProcessExited {
                exit_code,
                start_time: created,
                ..Default::default()
            },
        })
    }

    fn launched(pid: u32, time: u64, command_line: &str) -> Raw {
        Raw::Launched(Launched {
            pid,
            time,
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            command_line: command_line.into(),
        })
    }

    fn ended(pid: u32, sequence_number: u64, time: u64, exit_code: u32) -> Raw {
        ended_since(pid, sequence_number, time, time, exit_code)
    }

    fn started(event: &ProcessEvent) -> &ProcessStarted {
        match &event.kind {
            ProcessEventKind::Started(started) => started,
            ProcessEventKind::Exited(_) => panic!("{event:?} is an exit"),
        }
    }

    fn told(events: &[ProcessEvent]) -> Vec<(u32, u64, &'static str)> {
        events
            .iter()
            .map(|e| {
                let kind = match e.kind {
                    ProcessEventKind::Started(_) => "started",
                    ProcessEventKind::Exited(_) => "exited",
                };
                (e.pid, e.sequence_number, kind)
            })
            .collect()
    }

    #[test]
    fn a_start_takes_the_command_line_and_user_whichever_half_comes_first() {
        let mut assembler = Assembler::default();
        assembler.add(created(8, 80, T));
        assembler.add(launched(8, T + MS, "cmd /c \"exit 3\""));
        assembler.add(launched(9, T + 2 * MS, "git status"));
        assembler.add(created(9, 90, T + 2 * MS));
        let events = assembler.release(T + SECOND, &mut Machine);
        assert_eq!(told(&events), [(8, 80, "started"), (9, 90, "started")]);
        let first = started(&events[0]);
        assert_eq!(first.command_line, "cmd /c \"exit 3\"");
        assert_eq!(first.user, r"HOST\me");
        assert_eq!(first.image_path, r"C:\Windows\System32\cmd.exe");
        assert_eq!((first.parent_pid, first.parent_sequence_number, first.session_id), (600, 60, 1));
        assert_eq!(first.elevated, Some(false));
        assert_eq!(first.parent_services, ["Dnscache"]);
        assert_eq!(started(&events[1]).command_line, "git status");
    }

    #[test]
    fn what_goes_out_together_goes_out_in_order_of_time() {
        let mut assembler = Assembler::default();
        assembler.add(ended_since(1, 10, T - 3600 * SECOND, T + 5 * MS, 0));
        assembler.add(created(3, 30, T + 3 * MS));
        assembler.add(launched(3, T + 3 * MS, "c"));
        assembler.add(created(2, 20, T));
        assembler.add(launched(2, T, "b"));
        assert_eq!(
            told(&assembler.release(T + 6 * MS, &mut Machine)),
            [(2, 20, "started"), (3, 30, "started"), (1, 10, "exited")]
        );
        assert_eq!(told(&assembler.release(T + 7 * MS, &mut Machine)), []);
    }

    #[test]
    fn a_start_goes_out_before_its_exit_at_the_same_moment() {
        let mut assembler = Assembler::default();
        assembler.add(ended(4, 40, T, 7));
        assembler.add(created(4, 40, T));
        let events = assembler.release(T + WAITS_AT_MOST, &mut Machine);
        assert_eq!(told(&events), [(4, 40, "started"), (4, 40, "exited")]);
        assert!(matches!(events[1].kind, ProcessEventKind::Exited(ProcessExited { exit_code: 7, .. })));
    }

    #[test]
    fn a_start_whose_command_line_never_came_goes_out_without_one() {
        let mut assembler = Assembler::default();
        assembler.add(created(5, 50, T));
        let events = assembler.release(T + WAITS_AT_MOST, &mut Machine);
        assert_eq!(told(&events), [(5, 50, "started")]);
        assert_eq!(started(&events[0]).command_line, "");
        assert_eq!(started(&events[0]).user, "");
    }

    #[test]
    fn a_reused_pid_pairs_each_start_with_its_own_command_line() {
        let mut assembler = Assembler::default();
        assembler.add(launched(6, T, "first"));
        assembler.add(created(6, 61, T));
        assembler.add(ended(6, 61, T + 100 * MS, 0));
        assembler.add(created(6, 62, T + 3 * SECOND));
        assembler.add(launched(6, T + 3 * SECOND, "second"));
        let events = assembler.release(T + 4 * SECOND, &mut Machine);
        assert_eq!(told(&events), [(6, 61, "started"), (6, 61, "exited"), (6, 62, "started")]);
        assert_eq!(started(&events[0]).command_line, "first");
        assert_eq!(started(&events[2]).command_line, "second");
    }

    #[test]
    fn a_command_line_told_too_far_from_the_creation_is_not_its_own() {
        let mut assembler = Assembler::default();
        assembler.add(created(7, 70, T));
        assembler.add(launched(7, T + 2 * SECOND, "someone else"));
        let events = assembler.release(T + 10 * SECOND, &mut Machine);
        assert_eq!(told(&events), [(7, 70, "started")]);
        assert_eq!(started(&events[0]).command_line, "");
    }

    #[test]
    fn a_start_names_the_task_that_created_it() {
        let mut assembler = Assembler::default();
        assembler.add(created(11, 110, T));
        assembler.add(Raw::Scheduled(Scheduled {
            pid: 11,
            time: T + 30 * MS,
            task: r"\Microsoft\Windows\Defrag\ScheduledDefrag".into(),
        }));
        let events = assembler.release(T + WAITS_AT_MOST, &mut Machine);
        assert_eq!(told(&events), [(11, 110, "started")]);
        assert_eq!(started(&events[0]).scheduled_task, r"\Microsoft\Windows\Defrag\ScheduledDefrag");
    }

    #[test]
    fn a_start_waits_for_its_command_line_and_goes_out_as_soon_as_it_joins() {
        let mut assembler = Assembler::default();
        assembler.add(created(13, 130, T));
        assert_eq!(told(&assembler.release(T + 10 * MS, &mut Machine)), []);
        assembler.add(launched(13, T + MS, "late"));
        let events = assembler.release(T + 20 * MS, &mut Machine);
        assert_eq!(told(&events), [(13, 130, "started")]);
        assert_eq!(started(&events[0]).command_line, "late");
    }

    #[test]
    fn a_start_the_scheduler_made_waits_for_its_task_too() {
        let mut assembler = Assembler::default();
        assembler.add(Raw::Created(Created {
            parent_pid: 700,
            ..created_by(14, 140, T)
        }));
        assembler.add(launched(14, T, "task.exe"));
        assert_eq!(told(&assembler.release(T + 10 * MS, &mut Machine)), []);
        assembler.add(Raw::Scheduled(Scheduled {
            pid: 14,
            time: T + 5 * MS,
            task: r"\Nightly".into(),
        }));
        let events = assembler.release(T + 20 * MS, &mut Machine);
        assert_eq!(told(&events), [(14, 140, "started")]);
        assert_eq!(started(&events[0]).scheduled_task, r"\Nightly");
    }

    #[test]
    fn what_never_joins_goes_out_after_the_bound() {
        let mut assembler = Assembler::default();
        assembler.add(created(15, 150, T));
        assert_eq!(told(&assembler.release(T + WAITS_AT_MOST - MS, &mut Machine)), []);
        assert_eq!(told(&assembler.release(T + WAITS_AT_MOST, &mut Machine)), [(15, 150, "started")]);
    }

    #[test]
    fn an_exit_waits_for_its_start() {
        let mut assembler = Assembler::default();
        assembler.add(ended_since(16, 160, T, T + 5 * MS, 1));
        assert_eq!(told(&assembler.release(T + 10 * MS, &mut Machine)), []);
        assembler.add(created(16, 160, T));
        assembler.add(launched(16, T, "short"));
        assert_eq!(
            told(&assembler.release(T + 20 * MS, &mut Machine)),
            [(16, 160, "started"), (16, 160, "exited")]
        );
    }

    #[test]
    fn an_exit_goes_out_at_once_after_its_start_went_or_when_it_started_long_ago() {
        let mut assembler = Assembler::default();
        assembler.add(created(17, 170, T));
        assembler.add(launched(17, T, "a"));
        assert_eq!(told(&assembler.release(T + MS, &mut Machine)), [(17, 170, "started")]);
        assembler.add(ended_since(17, 170, T, T + 2 * MS, 0));
        assembler.add(ended_since(18, 180, T - 3600 * SECOND, T + 2 * MS, 0));
        assert_eq!(
            told(&assembler.release(T + 3 * MS, &mut Machine)),
            [(17, 170, "exited"), (18, 180, "exited")]
        );
    }

    #[test]
    fn halves_that_never_found_their_start_are_let_go() {
        let mut assembler = Assembler::default();
        assembler.add(launched(12, T, "orphan"));
        assembler.add(Raw::Scheduled(Scheduled {
            pid: 12,
            time: T,
            task: r"\Orphan".into(),
        }));
        assert_eq!(told(&assembler.release(T + 10 * SECOND, &mut Machine)), []);
        assembler.add(created(12, 120, T + 20 * SECOND));
        let events = assembler.release(T + 30 * SECOND, &mut Machine);
        assert_eq!(told(&events), [(12, 120, "started")]);
        assert_eq!(started(&events[0]).command_line, "");
        assert_eq!(started(&events[0]).scheduled_task, "");
        assert!(assembler.launched.is_empty() && assembler.scheduled.is_empty());
    }
}
