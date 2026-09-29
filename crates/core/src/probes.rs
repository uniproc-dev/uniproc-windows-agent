//! What a tick asks each process through a handle kept open for its lifetime.

use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use windows::Win32::{
    CloseHandle, GetCurrentProcessId, GetGuiResources, HANDLE, NtQueryInformationProcess,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, ProcessIdToSessionId,
};

use crate::model::IoPriority;
use crate::snapshot::Row;

const PROCESS_IO_PRIORITY: i32 = 33;
const PROCESS_POWER_THROTTLING_STATE: i32 = 77;
const POWER_THROTTLING_EXECUTION_SPEED: u32 = 1;
const GR_GDIOBJECTS: u32 = 0;
const GR_USEROBJECTS: u32 = 1;

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

unsafe impl Send for Owned {}

/// How long a probed value may be old: every listed process is probed again
/// within it.
pub const PROBE_ROUND: Duration = Duration::from_secs(10);

/// What a handle tells that the snapshot does not, as last probed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Probed {
    pub power_throttling: Option<bool>,
    pub io_priority: IoPriority,
}

struct Opened {
    sequence_number: u64,
    full: bool,
    handle: Option<Owned>,
    listed: u64,
    probed: Probed,
}

impl Opened {
    fn probe(&mut self) {
        if let Some(Owned(handle)) = self.handle {
            self.probed = Probed {
                power_throttling: power_throttling(handle),
                io_priority: io_priority(handle),
            };
        }
    }
}

/// One query handle per process, opened when it first shows up and closed
/// when it is gone: with full query rights where the process allows them,
/// otherwise limited ones. A process that could not be opened is not retried.
/// A process is probed as it shows up, then in turn by pid, so that each is
/// probed again within [`PROBE_ROUND`].
#[derive(Default)]
pub struct Handles {
    open: FxHashMap<u32, Opened>,
    synced: u64,
    last: Option<Instant>,
    cursor: u32,
}

impl Handles {
    /// Opens and probes the processes new to `rows`, reopens a reused pid,
    /// closes the gone, and probes the next turn of the rest. `rows` are
    /// ordered by pid.
    #[tracing::instrument(name = "handles", level = "debug", skip_all)]
    pub fn sync(&mut self, rows: &[Row]) {
        self.synced += 1;
        let now = self.synced;
        for row in rows {
            match self.open.get_mut(&row.pid) {
                Some(opened) if opened.sequence_number == row.sequence_number => opened.listed = now,
                _ => {
                    let full = crate::win::open_process(PROCESS_QUERY_INFORMATION, row.pid).ok();
                    let mut opened = Opened {
                        sequence_number: row.sequence_number,
                        full: full.is_some(),
                        handle: full
                            .or_else(|| crate::win::open_process(PROCESS_QUERY_LIMITED_INFORMATION, row.pid).ok())
                            .map(Owned),
                        listed: now,
                        probed: Probed::default(),
                    };
                    opened.probe();
                    self.open.insert(row.pid, opened);
                }
            }
        }
        self.open.retain(|_, opened| opened.listed == now);

        let at = Instant::now();
        let since = self.last.map_or(Duration::ZERO, |last| at - last);
        self.last = Some(at);
        let (start, share, next) = turn(rows, self.cursor, since);
        for row in rows.iter().cycle().skip(start).take(share) {
            if let Some(opened) = self.open.get_mut(&row.pid) {
                opened.probe();
            }
        }
        self.cursor = next;
    }

    pub fn get(&self, pid: u32) -> Option<HANDLE> {
        self.open.get(&pid)?.handle.as_ref().map(|owned| owned.0)
    }

    /// The handle when it was opened with full query rights, which D3DKMT
    /// needs; a protected process gives only limited ones.
    pub fn full(&self, pid: u32) -> Option<HANDLE> {
        let opened = self.open.get(&pid)?;
        opened.handle.as_ref().filter(|_| opened.full).map(|owned| owned.0)
    }

    /// The process's probed values; the default when it could not be read.
    pub fn probed(&self, pid: u32) -> Probed {
        self.open.get(&pid).map(|opened| opened.probed).unwrap_or_default()
    }

    #[cfg(test)]
    fn unopened(&self) -> usize {
        self.open.values().filter(|o| o.handle.is_none()).count()
    }
}

/// The rows to probe now, as the index of the first and how many from it
/// with wraparound: the share of the list that `since` is of
/// [`PROBE_ROUND`], from the first pid at or past `cursor`. Also where the
/// next turn starts.
pub(crate) fn turn(rows: &[Row], cursor: u32, since: Duration) -> (usize, usize, u32) {
    let share = (rows.len() as u128 * since.as_nanos()).div_ceil(PROBE_ROUND.as_nanos()) as usize;
    let share = share.min(rows.len());
    let start = rows.partition_point(|row| row.pid < cursor) % rows.len().max(1);
    let next = rows.get((start + share) % rows.len().max(1)).map_or(0, |row| row.pid);
    (start, share, next)
}

#[repr(C)]
#[derive(Default)]
struct PowerThrottlingState {
    version: u32,
    control_mask: u32,
    state_mask: u32,
}

/// Whether EcoQoS throttles the process.
pub fn power_throttling(handle: HANDLE) -> Option<bool> {
    let mut state = PowerThrottlingState {
        version: 1,
        ..Default::default()
    };
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_POWER_THROTTLING_STATE,
            &mut state as *mut PowerThrottlingState as *mut _,
            size_of::<PowerThrottlingState>() as u32,
            None,
        )
    };
    status
        .is_ok()
        .then_some(state.state_mask & POWER_THROTTLING_EXECUTION_SPEED != 0)
}

pub fn io_priority(handle: HANDLE) -> IoPriority {
    let mut hint = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_IO_PRIORITY,
            &mut hint as *mut u32 as *mut _,
            size_of::<u32>() as u32,
            None,
        )
    };
    if status.is_err() {
        return IoPriority::Unknown;
    }
    match hint {
        0 => IoPriority::VeryLow,
        1 => IoPriority::Low,
        2 => IoPriority::Normal,
        3 => IoPriority::High,
        4 => IoPriority::Critical,
        _ => IoPriority::Unknown,
    }
}

/// The session this process runs in; [`user_objects`] and [`gdi_objects`] answer only for it.
pub fn own_session() -> Option<u32> {
    let mut session = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }
        .as_bool()
        .then_some(session)
}

/// User objects the process holds. win32k answers only within the
/// caller's session: for a process of another one this is 0.
pub fn user_objects(handle: HANDLE) -> u32 {
    unsafe { GetGuiResources(handle, GR_USEROBJECTS) }
}

/// GDI objects the process holds; like [`user_objects`], only within the
/// caller's session.
pub fn gdi_objects(handle: HANDLE) -> u32 {
    unsafe { GetGuiResources(handle, GR_GDIOBJECTS) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me(sequence_number: u64) -> Row {
        Row {
            pid: std::process::id(),
            sequence_number,
            ..Default::default()
        }
    }

    #[test]
    fn this_process_is_opened_and_read() {
        let mut handles = Handles::default();
        handles.sync(&[me(1)]);
        let handle = handles.get(std::process::id()).expect("opened");
        assert!(power_throttling(handle).is_some());
        assert_ne!(io_priority(handle), IoPriority::Unknown);
        let _ = (user_objects(handle), gdi_objects(handle));
    }

    #[test]
    fn a_process_is_probed_as_it_shows_up() {
        let mut handles = Handles::default();
        handles.sync(&[me(1)]);
        let probed = handles.probed(std::process::id());
        assert!(probed.power_throttling.is_some());
        assert_ne!(probed.io_priority, IoPriority::Unknown);
        assert_eq!(handles.probed(0), Probed::default(), "nothing listed, nothing probed");
    }

    fn pids(pids: &[u32]) -> Vec<Row> {
        pids.iter().map(|&pid| Row { pid, ..Default::default() }).collect()
    }

    #[test]
    fn a_turn_is_the_share_of_the_list_its_time_is_of_the_round() {
        let rows = pids(&[4, 8, 12, 16, 20, 24, 28, 32, 36, 40]);
        assert_eq!(turn(&rows, 0, Duration::ZERO), (0, 0, 4));
        assert_eq!(turn(&rows, 0, PROBE_ROUND / 5), (0, 2, 12));
        assert_eq!(turn(&rows, 12, PROBE_ROUND / 5), (2, 2, 20));
        assert_eq!(turn(&rows, 0, PROBE_ROUND * 3), (0, 10, 4), "never more than the whole list");
    }

    #[test]
    fn turns_wrap_around_and_skip_a_pid_that_left() {
        let rows = pids(&[4, 8, 12, 16]);
        assert_eq!(turn(&rows, 12, PROBE_ROUND / 2), (2, 2, 4), "12 and 16, then back to 4");
        assert_eq!(turn(&rows, 10, PROBE_ROUND / 4), (2, 1, 16), "10 left: its turn goes to 12");
        assert_eq!(turn(&rows, 99, PROBE_ROUND / 4), (0, 1, 8), "past the last pid starts over");
        assert_eq!(turn(&[], 12, PROBE_ROUND), (0, 0, 0));
    }

    #[test]
    fn a_reused_pid_is_opened_again_and_a_gone_one_is_closed() {
        let mut handles = Handles::default();
        handles.sync(&[me(1)]);
        handles.sync(&[me(2)]);
        assert_eq!(handles.open[&std::process::id()].sequence_number, 2);
        handles.sync(&[]);
        assert!(handles.open.is_empty());
    }

    #[test]
    fn a_process_that_cannot_be_opened_is_kept_without_a_handle() {
        let mut handles = Handles::default();
        handles.sync(&[Row::default()]);
        assert_eq!(handles.unopened(), 1, "Idle has no process to open");
        assert!(handles.get(0).is_none());
    }
}
