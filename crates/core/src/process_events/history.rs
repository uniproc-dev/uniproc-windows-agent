//! The recent events, held for watchers: each reads on from where it was,
//! and is told how many it missed.

use std::collections::VecDeque;
use std::sync::Arc;

use smol_str::SmolStr;

use super::{ProcessEvent, ProcessEventBatch, ProcessEventKind};

pub(crate) struct History {
    entries: VecDeque<Entry>,
    /// The index of the first entry held: every event pushed has the next.
    first: u64,
    bytes: usize,
    history_from: u64,
    max_age: u64,
    max_bytes: usize,
    /// Dropped by the kernel since the last event pushed.
    lost: u32,
}

struct Entry {
    event: Arc<ProcessEvent>,
    bytes: usize,
    lost_before: u32,
}

/// About how much memory `event` takes while held.
pub(crate) fn event_bytes(event: &ProcessEvent) -> usize {
    let heap = |text: &SmolStr| if text.is_heap_allocated() { text.len() } else { 0 };
    let started = match &event.kind {
        ProcessEventKind::Started(s) => {
            heap(&s.image_path)
                + heap(&s.command_line)
                + heap(&s.user)
                + heap(&s.package_full_name)
                + heap(&s.working_directory)
                + heap(&s.scheduled_task)
                + s.parent_services.iter().map(|name| size_of::<SmolStr>() + heap(name)).sum::<usize>()
        }
        ProcessEventKind::Exited(_) => 0,
    };
    size_of::<Entry>() + size_of::<ProcessEvent>() + started
}

/// Where one watcher is in the history.
#[derive(Default)]
pub(crate) struct Cursor {
    next: u64,
    started: bool,
}

impl History {
    /// Holds what came after `started_at` for `max_age` FILETIME ticks, in at
    /// most about `max_bytes`.
    pub fn new(started_at: u64, max_age: u64, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            first: 0,
            bytes: 0,
            history_from: started_at,
            max_age,
            max_bytes,
            lost: 0,
        }
    }

    /// Holds `event`, letting go of what is older than the hold at `now` or
    /// does not fit; the newest event stays whatever its size.
    pub fn push(&mut self, event: ProcessEvent, now: u64) {
        let bytes = event_bytes(&event);
        self.entries.push_back(Entry {
            event: Arc::new(event),
            bytes,
            lost_before: std::mem::take(&mut self.lost),
        });
        self.bytes += bytes;
        let cutoff = now.saturating_sub(self.max_age);
        while let Some(oldest) = self.entries.front() {
            let too_old = oldest.event.time < cutoff;
            let too_many = self.bytes > self.max_bytes && self.entries.len() > 1;
            if !too_old && !too_many {
                break;
            }
            let gone = self.entries.pop_front().expect("the oldest entry");
            self.bytes -= gone.bytes;
            self.first += 1;
            self.history_from = gone.event.time + 1;
        }
    }

    /// The kernel dropped `count` events; the next one held carries that.
    pub fn kernel_lost(&mut self, count: u32) {
        self.lost = self.lost.saturating_add(count);
    }

    /// What the watcher at `cursor` has not read, in about `max_bytes` at
    /// most but at least one event; `None` when it has read everything.
    /// The first read always answers, to tell where the history begins.
    pub fn read(&self, cursor: &mut Cursor, max_bytes: usize) -> Option<ProcessEventBatch> {
        let first_read = !cursor.started;
        if first_read {
            cursor.started = true;
            cursor.next = self.first;
        }
        let mut lost = 0u32;
        if cursor.next < self.first {
            lost = u32::try_from(self.first - cursor.next).unwrap_or(u32::MAX);
            cursor.next = self.first;
        }
        let mut events = Vec::new();
        let mut bytes = 0;
        for entry in self.entries.range((cursor.next - self.first) as usize..) {
            if !events.is_empty() && bytes + entry.bytes > max_bytes {
                break;
            }
            bytes += entry.bytes;
            lost = lost.saturating_add(entry.lost_before);
            events.push(entry.event.clone());
        }
        cursor.next += events.len() as u64;
        if events.is_empty() && lost == 0 && !first_read {
            return None;
        }
        Some(ProcessEventBatch {
            history_from: if first_read { self.history_from } else { 0 },
            events,
            lost,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_events::assemble::SECOND;
    use crate::process_events::ProcessExited;

    const T: u64 = 134_000_000_000_000_000;
    const MINUTE: u64 = 60 * SECOND;
    const HOUR: u64 = 60 * MINUTE;
    const ROOMY: usize = 1 << 20;

    fn exit(pid: u32, time: u64) -> ProcessEvent {
        ProcessEvent {
            pid,
            sequence_number: pid as u64 * 10,
            time,
            kind: ProcessEventKind::Exited(ProcessExited::default()),
        }
    }

    fn pids(batch: &ProcessEventBatch) -> Vec<u32> {
        batch.events.iter().map(|e| e.pid).collect()
    }

    fn read(history: &History, cursor: &mut Cursor) -> Option<(u64, Vec<u32>, u32)> {
        history.read(cursor, ROOMY).map(|b| (b.history_from, pids(&b), b.lost))
    }

    #[test]
    fn a_new_watcher_gets_everything_held_and_then_only_what_is_new() {
        let mut history = History::new(T, HOUR, ROOMY);
        for pid in 1..=3 {
            history.push(exit(pid, T + pid as u64), T + pid as u64);
        }
        let mut cursor = Cursor::default();
        assert_eq!(read(&history, &mut cursor), Some((T, vec![1, 2, 3], 0)));
        assert_eq!(read(&history, &mut cursor), None);
        history.push(exit(4, T + 4), T + 4);
        assert_eq!(read(&history, &mut cursor), Some((0, vec![4], 0)));
    }

    #[test]
    fn the_first_read_of_an_empty_hold_still_tells_where_it_begins() {
        let history = History::new(T, HOUR, ROOMY);
        let mut cursor = Cursor::default();
        assert_eq!(read(&history, &mut cursor), Some((T, vec![], 0)));
        assert_eq!(read(&history, &mut cursor), None);
    }

    #[test]
    fn what_is_older_than_the_hold_leaves_it_and_the_history_begins_after() {
        let mut history = History::new(T, HOUR, ROOMY);
        history.push(exit(1, T), T);
        history.push(exit(2, T + 30 * MINUTE), T + 30 * MINUTE);
        history.push(exit(3, T + 90 * MINUTE), T + 90 * MINUTE);
        assert_eq!(read(&history, &mut Cursor::default()), Some((T + 1, vec![2, 3], 0)));
    }

    #[test]
    fn the_hold_keeps_within_its_bytes() {
        let one = event_bytes(&exit(1, T));
        let mut history = History::new(T, HOUR, 3 * one);
        for pid in 1..=10 {
            history.push(exit(pid, T + pid as u64), T + pid as u64);
        }
        assert_eq!(read(&history, &mut Cursor::default()), Some((T + 8, vec![8, 9, 10], 0)));
    }

    #[test]
    fn a_watcher_left_behind_by_the_hold_is_told_how_many_it_missed() {
        let one = event_bytes(&exit(1, T));
        let mut history = History::new(T, HOUR, 3 * one);
        history.push(exit(1, T + 1), T + 1);
        let mut cursor = Cursor::default();
        assert_eq!(read(&history, &mut cursor), Some((T, vec![1], 0)));
        for pid in 2..=7 {
            history.push(exit(pid, T + pid as u64), T + pid as u64);
        }
        assert_eq!(read(&history, &mut cursor), Some((0, vec![5, 6, 7], 3)));
    }

    #[test]
    fn what_the_kernel_dropped_reaches_every_watcher_with_the_next_event() {
        let mut history = History::new(T, HOUR, ROOMY);
        let (mut a, mut b) = (Cursor::default(), Cursor::default());
        assert!(read(&history, &mut a).is_some() && read(&history, &mut b).is_some());
        history.kernel_lost(3);
        assert_eq!(read(&history, &mut a), None, "told with the next event");
        history.push(exit(1, T + 1), T + 1);
        assert_eq!(read(&history, &mut a), Some((0, vec![1], 3)));
        assert_eq!(read(&history, &mut b), Some((0, vec![1], 3)));
        assert_eq!(read(&history, &mut Cursor::default()), Some((T, vec![1], 3)), "a late watcher too");
    }

    #[test]
    fn a_batch_keeps_under_its_bytes_but_carries_at_least_one_event() {
        let mut history = History::new(T, HOUR, ROOMY);
        for pid in 1..=5 {
            history.push(exit(pid, T + pid as u64), T + pid as u64);
        }
        let one = event_bytes(&exit(1, T));
        let mut cursor = Cursor::default();
        let mut batches = Vec::new();
        while let Some(batch) = history.read(&mut cursor, 2 * one + one / 2) {
            batches.push((batch.history_from, pids(&batch)));
        }
        assert_eq!(batches, [(T, vec![1, 2]), (0, vec![3, 4]), (0, vec![5])]);
        let mut cursor = Cursor::default();
        assert_eq!(history.read(&mut cursor, 1).map(|b| pids(&b)), Some(vec![1]));
    }
}
