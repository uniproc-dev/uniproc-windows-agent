//! A thread that probes listed processes on its own, so that a probe too
//! slow for the tick never holds it up.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;

use crate::snapshot::Row;

/// How long a probe stands, however still the process keeps.
pub const FULL_ROUND: Duration = Duration::from_secs(300);
/// The worker rests this many times as long as a probe took, so it keeps to
/// a quarter of a core.
const REST: u32 = 3;

/// A listed process as the worker is told of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listed {
    pub pid: u32,
    pub sequence_number: u64,
    /// `working_set - private_working_set`, as the snapshot had it.
    pub shared: u64,
}

/// What the worker saw of a process when it last probed it.
#[derive(Clone, Copy, Debug)]
pub struct Seen {
    pub sequence_number: u64,
    pub shared: u64,
    pub at: Instant,
}

/// Whether a process is to be probed now, given when it was last; `None`
/// when it never was under its sequence number.
pub type IsDue = fn(Option<&Seen>, &Listed, Instant) -> bool;

type Probed<T> = Arc<Mutex<FxHashMap<u32, (u64, T)>>>;

/// Probes the processes it is handed whenever `is_due` says so, one at a
/// time, and keeps each one's last answer; forgets a process once it is no
/// longer listed. The thread stops when this is dropped, after the process it
/// is probing.
pub struct Prober<T> {
    lists: Sender<Vec<Listed>>,
    probed: Probed<T>,
    stop: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl<T: Copy + Send + 'static> Prober<T> {
    pub fn start(name: &str, is_due: IsDue, probe: impl FnMut(u32) -> T + Send + 'static) -> Result<Self> {
        let (lists, listed) = crossbeam_channel::unbounded();
        let (stop, stopped) = crossbeam_channel::bounded(0);
        let probed: Probed<T> = Arc::new(Mutex::new(FxHashMap::default()));
        let worker = std::thread::Builder::new().name(name.into()).spawn({
            let probed = probed.clone();
            move || work(listed, stopped, probed, is_due, probe)
        })?;
        Ok(Self {
            lists,
            probed,
            stop: Some(stop),
            worker: Some(worker),
        })
    }

    /// Hands the worker the processes of `rows`; those it is not handed it
    /// forgets.
    pub fn read<'a>(&self, rows: impl IntoIterator<Item = &'a Row>) {
        let list = rows
            .into_iter()
            .map(|row| Listed {
                pid: row.pid,
                sequence_number: row.sequence_number,
                shared: shared(row),
            })
            .collect();
        let _ = self.lists.send(list);
    }

    /// The last answer for this process; `None` before its first probe.
    pub fn get(&self, row: &Row) -> Option<T> {
        match self.probed.lock().get(&row.pid) {
            Some(&(sequence_number, answer)) if sequence_number == row.sequence_number => Some(answer),
            _ => None,
        }
    }
}

impl<T> Drop for Prober<T> {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The part of the working set in pages that could be shared.
pub fn shared(row: &Row) -> u64 {
    row.working_set.saturating_sub(row.private_working_set)
}

fn work<T>(
    lists: Receiver<Vec<Listed>>,
    stopped: Receiver<()>,
    probed: Probed<T>,
    is_due: IsDue,
    mut probe: impl FnMut(u32) -> T,
) {
    let mut seen: FxHashMap<u32, Seen> = FxHashMap::default();
    loop {
        let mut list = crossbeam_channel::select! {
            recv(lists) -> list => match list {
                Ok(list) => list,
                Err(_) => return,
            },
            recv(stopped) -> _ => return,
        };
        if let Some(newer) = lists.try_iter().last() {
            list = newer;
        }
        let listed: FxHashMap<u32, u64> = list.iter().map(|l| (l.pid, l.sequence_number)).collect();
        let still_listed = |pid: &u32, sequence_number: u64| listed.get(pid) == Some(&sequence_number);
        seen.retain(|pid, last| still_listed(pid, last.sequence_number));
        probed.lock().retain(|pid, (sequence_number, _)| still_listed(pid, *sequence_number));

        let now = Instant::now();
        let due: Vec<Listed> = list.into_iter().filter(|l| is_due(seen.get(&l.pid), l, now)).collect();
        for l in due {
            if !lists.is_empty() {
                break;
            }
            let at = Instant::now();
            let answer = probe(l.pid);
            let took = at.elapsed();
            seen.insert(
                l.pid,
                Seen {
                    sequence_number: l.sequence_number,
                    shared: l.shared,
                    at,
                },
            );
            probed.lock().insert(l.pid, (l.sequence_number, answer));
            if !matches!(stopped.recv_timeout(took * REST), Err(RecvTimeoutError::Timeout)) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, sequence_number: u64) -> Row {
        Row {
            pid,
            sequence_number,
            ..Default::default()
        }
    }

    fn until<T: Copy + Send + 'static>(prober: &Prober<T>, row: &Row, done: impl Fn(Option<T>) -> bool) -> Option<T> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let answer = prober.get(row);
            if done(answer) || Instant::now() > deadline {
                return answer;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn always(_: Option<&Seen>, _: &Listed, _: Instant) -> bool {
        true
    }

    #[test]
    fn a_process_is_probed_and_forgotten_when_gone() {
        let prober = Prober::start("prober-test", always, |pid| pid * 2).unwrap();
        prober.read(&[row(8, 1)]);
        assert_eq!(until(&prober, &row(8, 1), |answer| answer.is_some()), Some(16));
        assert_eq!(prober.get(&row(8, 2)), None, "another process under the same pid");
        prober.read(&[]);
        assert_eq!(until(&prober, &row(8, 1), |answer| answer.is_none()), None);
    }

    #[test]
    fn a_worker_resting_after_a_probe_stops_at_once() {
        let probe = Duration::from_millis(400);
        let (done, probed) = crossbeam_channel::unbounded();
        let prober = Prober::start("prober-test", always, move |_| {
            std::thread::sleep(probe);
            let _ = done.send(());
        })
        .unwrap();
        prober.read(&[row(8, 1)]);
        probed.recv_timeout(Duration::from_secs(10)).expect("a probe");
        let at = Instant::now();
        drop(prober);
        assert!(at.elapsed() < probe * REST / 2, "stopped after {:?} of a {:?} rest", at.elapsed(), probe * REST);
    }
}
