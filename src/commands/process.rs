use crate::bindings::{
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, CloseHandle, HANDLE,
    HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, PROCESS_SET_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, REALTIME_PRIORITY_CLASS, SetPriorityClass,
    SetProcessAffinityMask, TerminateProcess,
};

use crate::api::{CommandResult, ProcessPriority};
use crate::win::{open_process, win32_code};

fn class(priority: ProcessPriority) -> i32 {
    match priority {
        ProcessPriority::Idle => IDLE_PRIORITY_CLASS,
        ProcessPriority::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
        ProcessPriority::Normal => NORMAL_PRIORITY_CLASS,
        ProcessPriority::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
        ProcessPriority::High => HIGH_PRIORITY_CLASS,
        ProcessPriority::Realtime => REALTIME_PRIORITY_CLASS,
    }
}

struct HandleGuard(HANDLE);

impl HandleGuard {
    fn open(access: i32, pid: u32) -> Result<Self, u32> {
        let handle = open_process(access, pid).map_err(|e| win32_code(&e))?;
        Ok(Self(handle))
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Win32 ERROR_ACCESS_DENIED: the agent does not stop or freeze itself.
const ERROR_ACCESS_DENIED: u32 = 5;

fn not_the_agent(pid: u32) -> CommandResult {
    if pid == std::process::id() { Err(ERROR_ACCESS_DENIED) } else { Ok(()) }
}

pub fn kill(pid: u32) -> CommandResult {
    not_the_agent(pid)?;
    let handle = HandleGuard::open(PROCESS_TERMINATE, pid)?;
    unsafe { TerminateProcess(handle.0, 1) }.ok().map_err(|e| win32_code(&e))
}

pub fn suspend(pid: u32) -> CommandResult {
    not_the_agent(pid)?;
    let handle = HandleGuard::open(PROCESS_SUSPEND_RESUME, pid)?;
    win32_result(unsafe { ntapi::ntpsapi::NtSuspendProcess(handle.0.0 as _) })
}

pub fn resume(pid: u32) -> CommandResult {
    let handle = HandleGuard::open(PROCESS_SUSPEND_RESUME, pid)?;
    win32_result(unsafe { ntapi::ntpsapi::NtResumeProcess(handle.0.0 as _) })
}

/// An NTSTATUS as the Win32 code every other command answers with.
fn win32_result(status: i32) -> CommandResult {
    if status >= 0 { Ok(()) } else { Err(unsafe { ntapi::ntrtl::RtlNtStatusToDosError(status) }) }
}

pub fn set_priority(pid: u32, priority: ProcessPriority) -> CommandResult {
    let handle = HandleGuard::open(PROCESS_SET_INFORMATION, pid)?;
    unsafe { SetPriorityClass(handle.0, class(priority) as u32) }.ok().map_err(|e| win32_code(&e))
}

pub fn set_affinity(pid: u32, mask: u64) -> CommandResult {
    let handle = HandleGuard::open(PROCESS_SET_INFORMATION, pid)?;
    unsafe { SetProcessAffinityMask(handle.0, mask as usize) }.ok().map_err(|e| win32_code(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

    #[test]
    fn a_failed_suspend_or_resume_answers_a_win32_code() {
        assert_eq!(win32_result(0), Ok(()));
        assert_eq!(win32_result(STATUS_ACCESS_DENIED as i32), Err(ERROR_ACCESS_DENIED));
        let terminating = win32_result(STATUS_PROCESS_IS_TERMINATING as i32);
        assert!(terminating.is_err_and(|code| code < 0x1_0000), "{terminating:?}");
    }
}
