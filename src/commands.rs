use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, SetPriorityClass, SetProcessAffinityMask, TerminateProcess,
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
    IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, PROCESS_SET_INFORMATION, PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE, REALTIME_PRIORITY_CLASS,
};
use uniproc_protocol::{ArchivedProcessCommand, ArchivedProcessPriority, CommandResult};

pub fn execute(cmd: &ArchivedProcessCommand) -> CommandResult {
    match cmd {
        ArchivedProcessCommand::Kill { pid } => kill(pid.into()),
        ArchivedProcessCommand::Suspend { pid } => suspend(pid.into()),
        ArchivedProcessCommand::Resume { pid } => resume(pid.into()),
        ArchivedProcessCommand::SetPriority { pid, priority } => set_priority(pid.into(), priority),
        ArchivedProcessCommand::SetAffinity { pid, mask } => set_affinity(pid.into(), mask.into()),
    }
}

fn kill(pid: u32) -> CommandResult {
    unsafe {
        let h = match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => h,
            Err(e) => return CommandResult::Err(e.code().0 as u32),
        };
        let result = TerminateProcess(h, 1);
        let _ = CloseHandle(h);
        match result {
            Ok(_) => CommandResult::Ok,
            Err(e) => CommandResult::Err(e.code().0 as u32),
        }
    }
}

fn suspend(pid: u32) -> CommandResult {
    unsafe {
        let h = match OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) {
            Ok(h) => h,
            Err(e) => return CommandResult::Err(e.code().0 as u32),
        };
        let status = ntapi::ntpsapi::NtSuspendProcess(h.0 as _);
        let _ = CloseHandle(h);
        if status >= 0 {
            CommandResult::Ok
        } else {
            CommandResult::Err(status as u32)
        }
    }
}

fn resume(pid: u32) -> CommandResult {
    unsafe {
        let h = match OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) {
            Ok(h) => h,
            Err(e) => return CommandResult::Err(e.code().0 as u32),
        };
        let status = ntapi::ntpsapi::NtResumeProcess(h.0 as _);
        let _ = CloseHandle(h);
        if status >= 0 {
            CommandResult::Ok
        } else {
            CommandResult::Err(status as u32)
        }
    }
}

fn set_priority(pid: u32, priority: &ArchivedProcessPriority) -> CommandResult {
    let class = match priority {
        ArchivedProcessPriority::Idle => IDLE_PRIORITY_CLASS,
        ArchivedProcessPriority::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
        ArchivedProcessPriority::Normal => NORMAL_PRIORITY_CLASS,
        ArchivedProcessPriority::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
        ArchivedProcessPriority::High => HIGH_PRIORITY_CLASS,
        ArchivedProcessPriority::Realtime => REALTIME_PRIORITY_CLASS,
    };
    unsafe {
        let h = match OpenProcess(PROCESS_SET_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(e) => return CommandResult::Err(e.code().0 as u32),
        };
        let result = SetPriorityClass(h, class);
        let _ = CloseHandle(h);
        match result {
            Ok(_) => CommandResult::Ok,
            Err(e) => CommandResult::Err(e.code().0 as u32),
        }
    }
}

fn set_affinity(pid: u32, mask: u64) -> CommandResult {
    unsafe {
        let h = match OpenProcess(PROCESS_SET_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(e) => return CommandResult::Err(e.code().0 as u32),
        };
        let result = SetProcessAffinityMask(h, mask as usize);
        let _ = CloseHandle(h);
        match result {
            Ok(_) => CommandResult::Ok,
            Err(e) => CommandResult::Err(e.code().0 as u32),
        }
    }
}
