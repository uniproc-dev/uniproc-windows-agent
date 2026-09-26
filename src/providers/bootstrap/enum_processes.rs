use anyhow::Result;
use ntapi::ntexapi::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION};
use windows::Win32::{NtQuerySystemInformation, SystemProcessInformation};

use crate::aligned::AlignedBuf;
use crate::providers::bootstrap::vars::{
    IDLE_PROCESS_PID, INITIAL_BUFFER_SIZE, KERNEL_PSEUDO_PROCESSES, STATUS_INFO_LENGTH_MISMATCH,
    SYSTEM_PROCESS_PID,
};

/// A pseudo-process of the kernel itself: Idle, System, and the few the
/// kernel starts under System with no image on disk. Decided by what the
/// process is, never by whether its image path could be read.
fn is_kernel_pseudo_process(pid: u32, parent_pid: u32, image_name: &str) -> bool {
    pid == IDLE_PROCESS_PID
        || pid == SYSTEM_PROCESS_PID
        || (parent_pid == SYSTEM_PROCESS_PID && KERNEL_PSEUDO_PROCESSES.contains(&image_name))
}
use crate::state::events::{ProcessStarted, StateChange};
use crate::providers::utils::{get_process_package_info, parse_cmd_line, query_command_line};

pub unsafe fn enum_processes() -> Result<Vec<StateChange>> {
    let probe_start = std::time::Instant::now();
    let mut buf_size = INITIAL_BUFFER_SIZE;
    let mut buf;

    loop {
        buf = AlignedBuf::zeroed(buf_size);
        let mut return_length = 0u32;

        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buf.as_mut_ptr() as *mut _,
                buf_size as u32,
                Some(&mut return_length),
            )
        };

        if status.is_ok() {
            tracing::warn!(
                returned_bytes = return_length,
                buffer_bytes = buf_size,
                micros = probe_start.elapsed().as_micros() as u64,
                "SystemProcessInformation probe"
            );
            break;
        }

        if status.0 == STATUS_INFO_LENGTH_MISMATCH {
            buf_size = return_length as usize + 4096;
            continue;
        }

        anyhow::bail!("NtQuerySystemInformation failed: {status:?}");
    }

    let mut changes = Vec::new();
    let mut offset = 0usize;

    loop {
        let start = unsafe { buf.as_ptr().add(offset) };
        let entry = unsafe { start.cast::<SYSTEM_PROCESS_INFORMATION>().read_unaligned() };

        let pid = entry.UniqueProcessId as u32;
        let parent_pid = entry.InheritedFromUniqueProcessId as u32;

        let image_name = if entry.ImageName.Length > 0 && !entry.ImageName.Buffer.is_null() {
            let units: Vec<u16> = (0..entry.ImageName.Length as usize / 2)
                .map(|i| unsafe { entry.ImageName.Buffer.add(i).read_unaligned() })
                .collect();
            String::from_utf16_lossy(&units)
        } else if pid == IDLE_PROCESS_PID {
            "System Idle Process".to_string()
        } else {
            "System".to_string()
        };

        let is_kernel_process = is_kernel_pseudo_process(pid, parent_pid, &image_name);

        let (cmd_lines, package_full_name, package_relative_app_id) = if is_kernel_process {
            (Vec::new(), String::new(), String::new())
        } else {
            let command_line = unsafe { query_command_line(pid).unwrap_or_default() };
            let (package_full_name, package_relative_app_id) =
                unsafe { get_process_package_info(pid).unwrap_or_default() };
            (
                unsafe { parse_cmd_line(&command_line) },
                package_full_name,
                package_relative_app_id,
            )
        };

        changes.push(StateChange::ProcessRundown(Box::new(ProcessStarted {
            pid,
            parent_pid,
            session_id: entry.SessionId,
            image_name,
            command_line: cmd_lines,
            package_full_name,
            package_relative_app_id,
            is_kernel_process,
        })));

        let threads_ptr = unsafe {
            start
                .add(size_of::<SYSTEM_PROCESS_INFORMATION>())
                .cast::<SYSTEM_THREAD_INFORMATION>()
        };

        for i in 0..entry.NumberOfThreads as usize {
            let thread = unsafe { threads_ptr.add(i).read_unaligned() };
            let tid = thread.ClientId.UniqueThread as u32;
            if tid != 0 {
                changes.push(StateChange::ThreadStarted { pid, tid });
            }
        }

        if entry.NextEntryOffset == 0 {
            break;
        }
        offset += entry.NextEntryOffset as usize;
    }

    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::is_kernel_pseudo_process;

    #[test]
    fn idle_and_system_are_kernel_whatever_they_are_called() {
        assert!(is_kernel_pseudo_process(0, 0, "System Idle Process"));
        assert!(is_kernel_pseudo_process(4, 0, "System"));
    }

    #[test]
    fn imageless_processes_the_kernel_starts_are_kernel() {
        for name in ["Registry", "Memory Compression", "Secure System"] {
            assert!(is_kernel_pseudo_process(232, 4, name), "{name}");
        }
    }

    #[test]
    fn a_system32_binary_of_another_account_is_not_kernel() {
        for name in ["csrss.exe", "dwm.exe", "fontdrvhost.exe", "NgcIso.exe", "vmmemWSL"] {
            assert!(!is_kernel_pseudo_process(1072, 880, name), "{name}");
        }
    }

    #[test]
    fn borrowing_a_kernel_name_is_not_enough() {
        assert!(!is_kernel_pseudo_process(9000, 5120, "Registry"));
        assert!(!is_kernel_pseudo_process(9001, 5120, "Memory Compression"));
    }
}
