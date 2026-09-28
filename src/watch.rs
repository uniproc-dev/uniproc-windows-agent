use std::cmp::Ordering;
use std::sync::Arc;

use crate::api::{Changes, MetricSpec, Snapshot, Update};
use crate::feed::Published;
use crate::sampler::LocalSampler;

/// A watch on the agent running in this process: every sample this
/// subscription is due, with the lists it was taken against and what moved
/// in them. The core samples for it until it is dropped.
pub struct LocalWatch {
    sampler: LocalSampler,
    last: Option<Arc<Published>>,
}

impl LocalWatch {
    pub(crate) fn new(sampler: LocalSampler) -> Self {
        Self { sampler, last: None }
    }

    pub fn spec(&self) -> MetricSpec {
        self.sampler.spec()
    }

    /// The next update; the first carries everything. Paced at the spec's
    /// interval, the latest sample winning while nobody asks.
    pub async fn next(&mut self) -> Update {
        let since = self.last.as_ref().map_or(0, |last| last.sample.snapshot);
        let published = self.sampler.published(since).await;
        let changes = changes(self.last.as_ref().map(|last| &last.snapshot), &published.snapshot);
        let update = Update {
            snapshot: published.snapshot.clone(),
            sample: published.sample.project(&self.sampler.spec()),
            changes,
        };
        self.last = Some(published);
        update
    }
}

/// What moved from `before` to `after`; everything when nothing came before.
pub(crate) fn changes(before: Option<&Snapshot>, after: &Snapshot) -> Changes {
    let states = &after.states.value.states;
    let Some(before) = before else {
        return Changes {
            full: true,
            passports: after.processes.value.iter().map(|p| (p.pid, p.sequence_number)).collect(),
            left: Vec::new(),
            states: states.iter().map(|s| (s.pid, s.sequence_number)).collect(),
            services: true,
        };
    };
    let mut changes = Changes {
        services: before.services.etag != after.services.etag,
        ..Changes::default()
    };
    if before.processes.etag != after.processes.etag {
        diff(
            &before.processes.value,
            &after.processes.value,
            |p| (p.pid, p.sequence_number),
            &mut changes.passports,
            &mut changes.left,
        );
    }
    if before.states.etag != after.states.etag {
        diff(
            &before.states.value.states,
            states,
            |s| (s.pid, s.sequence_number),
            &mut changes.states,
            &mut Vec::new(),
        );
    }
    changes
}

/// Walks two lists ordered by pid: rows new or changed in `after` go to
/// `upserted`, rows no longer there to `left`.
fn diff<T: PartialEq>(
    before: &[T],
    after: &[T],
    key: impl Fn(&T) -> (u32, u64),
    upserted: &mut Vec<(u32, u64)>,
    left: &mut Vec<(u32, u64)>,
) {
    let (mut i, mut j) = (0, 0);
    loop {
        match (before.get(i), after.get(j)) {
            (Some(was), Some(is)) => {
                let (was_key, is_key) = (key(was), key(is));
                match was_key.0.cmp(&is_key.0) {
                    Ordering::Less => {
                        left.push(was_key);
                        i += 1;
                    }
                    Ordering::Greater => {
                        upserted.push(is_key);
                        j += 1;
                    }
                    Ordering::Equal => {
                        if was_key != is_key {
                            left.push(was_key);
                            upserted.push(is_key);
                        } else if was != is {
                            upserted.push(is_key);
                        }
                        i += 1;
                        j += 1;
                    }
                }
            }
            (Some(was), None) => {
                left.push(key(was));
                i += 1;
            }
            (None, Some(is)) => {
                upserted.push(key(is));
                j += 1;
            }
            (None, None) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ProcessInfo, ProcessState, ProcessStates, ServiceStats, Tagged};

    fn info(pid: u32, sequence_number: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            sequence_number,
            ..Default::default()
        }
    }

    fn state(pid: u32, sequence_number: u64) -> ProcessState {
        ProcessState {
            pid,
            sequence_number,
            ..Default::default()
        }
    }

    fn snapshot(etags: (u64, u64, u64), processes: Vec<ProcessInfo>, states: Vec<ProcessState>) -> Snapshot {
        Snapshot {
            services: Tagged {
                etag: etags.2,
                value: Arc::from([ServiceStats::default()]),
            },
            processes: Tagged {
                etag: etags.0,
                value: processes.into(),
            },
            states: Tagged {
                etag: etags.1,
                value: ProcessStates {
                    passport_etag: etags.0,
                    states: states.into(),
                },
            },
        }
    }

    #[test]
    fn the_first_update_carries_everything() {
        let after = snapshot((1, 1, 1), vec![info(4, 1), info(8, 2)], vec![state(4, 1), state(8, 2)]);
        let changes = changes(None, &after);
        assert!(changes.full && changes.services);
        assert_eq!(changes.passports, [(4, 1), (8, 2)]);
        assert_eq!(changes.states, [(4, 1), (8, 2)]);
        assert!(changes.left.is_empty());
    }

    #[test]
    fn a_process_that_starts_exits_changes_or_takes_a_reused_pid_is_named() {
        let before = snapshot(
            (1, 1, 1),
            vec![info(4, 1), info(8, 2), info(12, 3), info(16, 4)],
            vec![state(4, 1), state(8, 2), state(12, 3), state(16, 4)],
        );
        let renamed = ProcessInfo {
            display_name: "Twelve".into(),
            ..info(12, 3)
        };
        let suspended = ProcessState {
            suspended: Some(true),
            ..state(4, 1)
        };
        let after = snapshot(
            (2, 2, 1),
            vec![info(4, 1), renamed, info(16, 9), info(20, 5)],
            vec![suspended, state(12, 3), state(16, 9), state(20, 5)],
        );
        let changes = changes(Some(&before), &after);
        assert!(!changes.full && !changes.services);
        assert_eq!(changes.passports, [(12, 3), (16, 9), (20, 5)]);
        assert_eq!(changes.left, [(8, 2), (16, 4)]);
        assert_eq!(changes.states, [(4, 1), (16, 9), (20, 5)]);
    }

    #[test]
    fn lists_under_the_same_tags_are_not_compared() {
        let before = snapshot((1, 1, 1), vec![info(4, 1)], vec![state(4, 1)]);
        let after = snapshot((1, 1, 2), vec![info(4, 1), info(8, 2)], vec![state(4, 1)]);
        let changes = changes(Some(&before), &after);
        assert!(changes.passports.is_empty() && changes.states.is_empty());
        assert!(changes.services);
    }
}
