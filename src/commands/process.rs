use windows::Win32::{
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, CloseHandle, HANDLE,
    HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, PROCESS_SET_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, REALTIME_PRIORITY_CLASS, SetPriorityClass,
    SetProcessAffinityMask, TerminateProcess,
};

use crate::commands::Outcome;
use crate::commands::services::win32_code;
use crate::win::open_process;

#[derive(Clone, Copy)]
pub enum ProcessPriority {
    Idle,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    Realtime,
}

impl ProcessPriority {
    fn class(self) -> i32 {
        match self {
            Self::Idle => IDLE_PRIORITY_CLASS,
            Self::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
            Self::Normal => NORMAL_PRIORITY_CLASS,
            Self::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
            Self::High => HIGH_PRIORITY_CLASS,
            Self::Realtime => REALTIME_PRIORITY_CLASS,
        }
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

pub fn kill(pid: u32) -> Outcome {
    let handle = HandleGuard::open(PROCESS_TERMINATE, pid)?;
    unsafe { TerminateProcess(handle.0, 1) }.ok().map_err(|e| win32_code(&e))
}

pub fn suspend(pid: u32) -> Outcome {
    let handle = HandleGuard::open(PROCESS_SUSPEND_RESUME, pid)?;
    // NTSTATUS, not a Win32 code.
    let status = unsafe { ntapi::ntpsapi::NtSuspendProcess(handle.0.0 as _) };
    if status >= 0 { Ok(()) } else { Err(status as u32) }
}

pub fn resume(pid: u32) -> Outcome {
    let handle = HandleGuard::open(PROCESS_SUSPEND_RESUME, pid)?;
    // NTSTATUS, not a Win32 code.
    let status = unsafe { ntapi::ntpsapi::NtResumeProcess(handle.0.0 as _) };
    if status >= 0 { Ok(()) } else { Err(status as u32) }
}

pub fn set_priority(pid: u32, priority: ProcessPriority) -> Outcome {
    let handle = HandleGuard::open(PROCESS_SET_INFORMATION, pid)?;
    unsafe { SetPriorityClass(handle.0, priority.class() as u32) }.ok().map_err(|e| win32_code(&e))
}

pub fn set_affinity(pid: u32, mask: u64) -> Outcome {
    let handle = HandleGuard::open(PROCESS_SET_INFORMATION, pid)?;
    unsafe { SetProcessAffinityMask(handle.0, mask as usize) }.ok().map_err(|e| win32_code(&e))
}
