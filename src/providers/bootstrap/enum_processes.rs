use anyhow::Result;
use ntapi::ntexapi::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};

use crate::providers::bootstrap::vars::{
    IDLE_PROCESS_PID, INITIAL_BUFFER_SIZE, STATUS_INFO_LENGTH_MISMATCH, SYSTEM_PROCESS_PID,
};
use crate::state::events::{ProcessStarted, StateChange};
use crate::providers::utils::{get_process_package_info, parse_cmd_line, query_command_line};

pub unsafe fn enum_processes() -> Result<Vec<StateChange>> {
    let mut buf_size = INITIAL_BUFFER_SIZE;
    let mut buf;

    loop {
        buf = vec![0u8; buf_size];
        let mut return_length = 0u32;

        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buf.as_mut_ptr() as *mut _,
                buf_size as u32,
                &mut return_length,
            )
        };

        if status.is_ok() {
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
        let entry = unsafe { &*(buf.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION) };

        let pid = entry.UniqueProcessId as u32;
        // Kernel pseudo-processes have no image file to query.
        let is_kernel_process = pid == IDLE_PROCESS_PID || pid == SYSTEM_PROCESS_PID;

        let image_name = if entry.ImageName.Length > 0 && !entry.ImageName.Buffer.is_null() {
            let slice = unsafe {
                std::slice::from_raw_parts(
                    entry.ImageName.Buffer,
                    entry.ImageName.Length as usize / 2,
                )
            };
            String::from_utf16_lossy(slice)
        } else if pid == IDLE_PROCESS_PID {
            "System Idle Process".to_string()
        } else {
            "System".to_string()
        };

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

        changes.push(StateChange::ProcessRundown(ProcessStarted {
            pid,
            parent_pid: entry.InheritedFromUniqueProcessId as u32,
            session_id: entry.SessionId,
            image_name,
            command_line: cmd_lines,
            package_full_name,
            package_relative_app_id,
            is_kernel_process,
        }));

        let threads_ptr = unsafe {
            (buf.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION).add(1)
                as *const SYSTEM_THREAD_INFORMATION
        };

        for i in 0..entry.NumberOfThreads as usize {
            let thread = unsafe { &*threads_ptr.add(i) };
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
