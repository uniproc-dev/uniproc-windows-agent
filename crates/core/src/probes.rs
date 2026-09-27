//! What a tick asks each process through a handle kept open for its lifetime.

use fxhash::FxHashMap;
use windows::Win32::{
    CloseHandle, GetCurrentProcessId, GetGuiResources, HANDLE, NtQueryInformationProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, ProcessIdToSessionId,
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

struct Opened {
    sequence_number: u64,
    handle: Option<Owned>,
}

/// One limited-query handle per process, opened when it first shows up and
/// closed when it is gone. A process that could not be opened is not retried.
#[derive(Default)]
pub struct Handles {
    open: FxHashMap<u32, Opened>,
}

impl Handles {
    /// Opens the processes new to `rows`, reopens a reused pid, closes the gone.
    pub fn sync(&mut self, rows: &[Row]) {
        let mut seen = FxHashMap::default();
        for row in rows {
            seen.insert(row.pid, row.sequence_number);
            let fresh = self
                .open
                .get(&row.pid)
                .is_none_or(|opened| opened.sequence_number != row.sequence_number);
            if fresh {
                let handle = crate::win::open_process(PROCESS_QUERY_LIMITED_INFORMATION, row.pid)
                    .ok()
                    .map(Owned);
                self.open.insert(
                    row.pid,
                    Opened {
                        sequence_number: row.sequence_number,
                        handle,
                    },
                );
            }
        }
        self.open.retain(|pid, opened| seen.get(pid) == Some(&opened.sequence_number));
    }

    pub fn get(&self, pid: u32) -> Option<HANDLE> {
        self.open.get(&pid)?.handle.as_ref().map(|owned| owned.0)
    }

    #[cfg(test)]
    fn unopened(&self) -> usize {
        self.open.values().filter(|o| o.handle.is_none()).count()
    }
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

/// The session this process runs in; [`gui_objects`] answers only for it.
pub fn own_session() -> Option<u32> {
    let mut session = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }
        .as_bool()
        .then_some(session)
}

/// User objects and GDI objects the process holds. win32k answers only
/// within the caller's session: for a process of another one this is 0.
pub fn gui_objects(handle: HANDLE) -> (u32, u32) {
    unsafe {
        (
            GetGuiResources(handle, GR_USEROBJECTS),
            GetGuiResources(handle, GR_GDIOBJECTS),
        )
    }
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
        let _ = gui_objects(handle);
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
