use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
    IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_CREATION_FLAGS, PROCESS_SET_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    REALTIME_PRIORITY_CLASS, SetPriorityClass, SetProcessAffinityMask, TerminateProcess,
};

use crate::commands::Outcome;
use crate::commands::services::win32_code;

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
    fn class(self) -> PROCESS_CREATION_FLAGS {
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
    fn open(access: PROCESS_ACCESS_RIGHTS, pid: u32) -> Result<Self, u32> {
        let handle =
            unsafe { OpenProcess(access, false, pid) }.map_err(|e| win32_code(&e))?;
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
    unsafe { TerminateProcess(handle.0, 1) }.map_err(|e| win32_code(&e))
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
    unsafe { SetPriorityClass(handle.0, priority.class()) }.map_err(|e| win32_code(&e))
}

pub fn set_affinity(pid: u32, mask: u64) -> Outcome {
    let handle = HandleGuard::open(PROCESS_SET_INFORMATION, pid)?;
    unsafe { SetProcessAffinityMask(handle.0, mask as usize) }.map_err(|e| win32_code(&e))
}
