//! Every interval the demand asks for, kept on time apart from the others.

use std::time::Instant;

use crate::sample::MetricSpec;

/// What one tick samples: everything due, at the shortest due interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Due {
    pub spec: MetricSpec,
    /// A due spec reads the process list; otherwise only the machine is read.
    pub reads_processes: bool,
}

/// The intervals of the demand, each with the union of what is wanted at
/// it and when it was last sampled on time.
#[derive(Default)]
pub struct Schedule {
    cadences: Vec<Cadence>,
}

struct Cadence {
    spec: MetricSpec,
    on_time: Instant,
    sampled_for: MetricSpec,
}

impl Schedule {
    /// What to sample at `now` for `specs`: every interval that is due, new,
    /// or wants more than it was last sampled for. A sample taken because an
    /// interval wants more does not move when that interval is next due.
    pub fn take(&mut self, specs: &[MetricSpec], now: Instant) -> Option<Due> {
        let mut before = std::mem::take(&mut self.cadences);
        let mut taken: Option<Due> = None;
        for (spec, reads_processes) in by_interval(specs) {
            let known = before
                .iter()
                .position(|c| c.spec.interval == spec.interval)
                .map(|at| before.swap_remove(at));
            let due = known.as_ref().is_none_or(|c| now >= c.on_time + spec.interval);
            let grown = known.as_ref().is_none_or(|c| !c.sampled_for.covers(&spec));
            let on_time = match &known {
                Some(c) if !due => c.on_time,
                _ => now,
            };
            let sampled_for = match known {
                Some(c) if !due && !grown => c.sampled_for,
                _ => {
                    taken = Some(match taken {
                        Some(t) => Due {
                            spec: t.spec.union(spec),
                            reads_processes: t.reads_processes || reads_processes,
                        },
                        None => Due { spec, reads_processes },
                    });
                    spec
                }
            };
            self.cadences.push(Cadence {
                spec,
                on_time,
                sampled_for,
            });
        }
        taken
    }

    /// When the next interval is due; None before the first take.
    pub fn due(&self) -> Option<Instant> {
        self.cadences.iter().map(|c| c.on_time + c.spec.interval).min()
    }
}

/// The specs grouped by their clamped interval, each group the union of
/// its specs, and whether any of them reads the process list.
fn by_interval(specs: &[MetricSpec]) -> Vec<(MetricSpec, bool)> {
    let mut groups: Vec<(MetricSpec, bool)> = Vec::new();
    for spec in specs {
        let clamped = MetricSpec {
            interval: spec.period(),
            ..*spec
        };
        match groups.iter_mut().find(|(g, _)| g.interval == clamped.interval) {
            Some((group, reads)) => {
                *group = group.union(clamped);
                *reads |= spec.reads_processes();
            }
            None => groups.push((clamped, spec.reads_processes())),
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::sample::{MachineMetric, MachineMetrics, ProcessMetric, ProcessMetrics};

    fn machine(ms: u64) -> MetricSpec {
        MetricSpec {
            interval: Duration::from_millis(ms),
            processes: ProcessMetrics::empty(),
            machine: MachineMetric::Cpu.into(),
        }
    }

    fn processes(ms: u64) -> MetricSpec {
        MetricSpec {
            interval: Duration::from_millis(ms),
            processes: ProcessMetric::Handles.into(),
            machine: MachineMetrics::empty(),
        }
    }

    fn at(start: Instant, ms: u64) -> Instant {
        start + Duration::from_millis(ms)
    }

    #[test]
    fn each_interval_is_sampled_on_its_own_time() {
        let specs = [machine(200), processes(1000)];
        let start = Instant::now();
        let mut schedule = Schedule::default();
        let first = schedule.take(&specs, start).unwrap();
        assert!(first.reads_processes);
        assert_eq!(first.spec.interval, Duration::from_millis(200));

        let mut read = Vec::new();
        for ms in (200..=1000).step_by(200) {
            let due = schedule.take(&specs, at(start, ms)).unwrap();
            read.push((ms, due.reads_processes, due.spec.processes.is_empty()));
        }
        assert_eq!(
            read,
            [
                (200, false, true),
                (400, false, true),
                (600, false, true),
                (800, false, true),
                (1000, true, false),
            ]
        );
        assert_eq!(schedule.due(), Some(at(start, 1200)));
        assert_eq!(schedule.take(&specs, at(start, 1100)), None);
    }

    #[test]
    fn a_machine_only_spec_does_not_read_the_process_list_but_a_lists_only_one_does() {
        let lists = MetricSpec::idle(Duration::from_secs(2));
        assert!(!machine(100).reads_processes());
        assert!(lists.reads_processes());
        assert!(processes(100).reads_processes());

        let start = Instant::now();
        let mut schedule = Schedule::default();
        let specs = [machine(100), lists];
        schedule.take(&specs, start);
        assert!(!schedule.take(&specs, at(start, 100)).unwrap().reads_processes);
        assert!(!schedule.take(&specs, at(start, 1900)).unwrap().reads_processes);
        assert!(schedule.take(&specs, at(start, 2000)).unwrap().reads_processes);
    }

    #[test]
    fn specs_at_one_interval_are_sampled_together() {
        let mut both = machine(500);
        both.processes = ProcessMetric::Threads.into();
        let specs = [processes(500), both];
        let due = Schedule::default().take(&specs, Instant::now()).unwrap();
        assert_eq!(due.spec.processes, ProcessMetric::Handles | ProcessMetric::Threads);
        assert_eq!(due.spec.machine, MachineMetrics::only(MachineMetric::Cpu));
    }

    #[test]
    fn an_interval_that_wants_more_is_sampled_at_once_without_moving() {
        let start = Instant::now();
        let mut schedule = Schedule::default();
        schedule.take(&[processes(1000)], start);
        let mut wider = processes(1000);
        wider.processes |= ProcessMetric::Threads;
        let grown = schedule.take(&[wider], at(start, 300)).unwrap();
        assert!(grown.spec.processes.contains(ProcessMetric::Threads));
        assert_eq!(schedule.due(), Some(at(start, 1000)), "still due a period after the last on time");
        assert_eq!(schedule.take(&[wider], at(start, 400)), None);
    }

    #[test]
    fn a_new_interval_is_sampled_at_once_and_a_gone_one_forgotten() {
        let start = Instant::now();
        let mut schedule = Schedule::default();
        schedule.take(&[processes(1000)], start);
        let fast = schedule.take(&[processes(1000), machine(100)], at(start, 50)).unwrap();
        assert!(!fast.reads_processes);
        assert_eq!(schedule.due(), Some(at(start, 150)));
        schedule.take(&[processes(1000)], at(start, 60));
        assert_eq!(schedule.due(), Some(at(start, 1000)));
    }

    #[test]
    fn intervals_out_of_range_are_clamped_before_they_are_grouped() {
        let start = Instant::now();
        let mut schedule = Schedule::default();
        let due = schedule.take(&[processes(0), machine(50)], start).unwrap();
        assert_eq!(due.spec.interval, crate::sample::MIN_INTERVAL);
        assert_eq!(due.spec.machine, MachineMetrics::only(MachineMetric::Cpu));
        assert!(due.reads_processes);
        assert_eq!(schedule.due(), Some(start + crate::sample::MIN_INTERVAL), "one interval, not two");
    }
}
