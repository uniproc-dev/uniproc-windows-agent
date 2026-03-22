use anyhow::Result;
use parking_lot::Mutex;
use std::sync::Arc;
use ntapi::ntexapi::{SYSTEM_THREAD_INFORMATION, SYSTEM_PROCESS_INFORMATION};
use tracing::{debug, info};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::PEB;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::collector::provider::{ProcessMap, Provider};
use crate::collector::state::{ProcessStarted, StateChange};
use crate::etw::kernel_session::KernelSessionRouter;


#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    reserved: usize,
    peb_base_address: *mut u8,
    reserved2: [usize; 2],
    unique_process_id: usize,
    reserved3: usize,
}

#[repr(C)]
struct RTL_USER_PROCESS_PARAMETERS {
    _reserved: [u8; 112],
    command_line: windows::Win32::Foundation::UNICODE_STRING,
}

pub struct BootstrapProvider {
    queue: Arc<Mutex<Vec<StateChange>>>,
}

impl BootstrapProvider {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

unsafe fn query_command_line(pid: u32) -> Option<String> {
    let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

    let mut pbi = PROCESS_BASIC_INFORMATION {
        reserved: 0,
        peb_base_address: std::ptr::null_mut(),
        reserved2: [0; 2],
        unique_process_id: 0,
        reserved3: 0,
    };

    let status = NtQueryInformationProcess(
        handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as *mut _,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        std::ptr::null_mut(),
    );

    if status.is_err() {
        CloseHandle(handle).ok();
        return None;
    }

    let mut peb = std::mem::zeroed::<PEB>();
    let ok = ReadProcessMemory(
        handle,
        pbi.peb_base_address as *const _,
        &mut peb as *mut _ as *mut _,
        std::mem::size_of::<PEB>(),
        None,
    );
    if ok.is_err() {
        CloseHandle(handle).ok();
        return None;
    }

    let mut params = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
    let ok = ReadProcessMemory(
        handle,
        peb.ProcessParameters as *const _,
        &mut params as *mut _ as *mut _,
        std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(),
        None,
    );
    if ok.is_err() {
        CloseHandle(handle).ok();
        return None;
    }

    let len = params.command_line.Length as usize / 2;
    let mut buf = vec![0u16; len];
    let ok = ReadProcessMemory(
        handle,
        params.command_line.Buffer.0 as *const _,
        buf.as_mut_ptr() as *mut _,
        params.command_line.Length as usize,
        None,
    );

    CloseHandle(handle).ok();

    if ok.is_err() {
        return None;
    }

    Some(String::from_utf16_lossy(&buf))
}

unsafe fn enum_processes() -> Result<Vec<StateChange>> {
    let mut buf_size = 1024 * 1024usize;
    let mut buf;

    loop {
        buf = vec![0u8; buf_size];
        let mut return_length = 0u32;

        let status = NtQuerySystemInformation(
            SystemProcessInformation,
            buf.as_mut_ptr() as *mut _,
            buf_size as u32,
            &mut return_length,
        );

        if status.is_ok() {
            break;
        }

        if status.0 == 0xC0000004u32 as i32 {
            buf_size = return_length as usize + 4096;
            continue;
        }

        anyhow::bail!("NtQuerySystemInformation failed: {status:?}");
    }

    let mut changes = Vec::new();
    let mut offset = 0usize;

    loop {
        let entry = &*(buf.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION);

        let pid = entry.UniqueProcessId as u32;

        if pid != 0 {
            let image_name = if entry.ImageName.Length > 0 && !entry.ImageName.Buffer.is_null() {
                let slice = std::slice::from_raw_parts(
                    entry.ImageName.Buffer,
                    entry.ImageName.Length as usize / 2,
                );
                String::from_utf16_lossy(slice)
            } else {
                "System".to_string()
            };

            let command_line = query_command_line(pid).unwrap_or_default();

            changes.push(StateChange::ProcessRundown(ProcessStarted {
                pid,
                parent_pid: entry.InheritedFromUniqueProcessId as u32,
                session_id: entry.SessionId,
                image_name,
                command_line,
            }));

            let threads_ptr = (buf.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION).add(1)
                as *const SYSTEM_THREAD_INFORMATION;

            for i in 0..entry.NumberOfThreads as usize {
                let thread = &*threads_ptr.add(i);
                let tid = thread.ClientId.UniqueThread as u32;
                if tid != 0 {
                    changes.push(StateChange::ThreadStarted { pid, tid });
                }
            }

        }

        if entry.NextEntryOffset == 0 {
            break;
        }
        offset += entry.NextEntryOffset as usize;
    }

    Ok(changes)
}

impl Provider for BootstrapProvider {
    fn start(&self, _processes: ProcessMap, _kernel: Arc<KernelSessionRouter>) -> Result<()> {
        let changes = unsafe { enum_processes()? };
        *self.queue.lock() = changes;
        Ok(())
    }

    fn stop(&self) {}

    fn drain(&self) -> Vec<StateChange> {
        std::mem::take(&mut *self.queue.lock())
    }

    fn is_oneshot(&self) -> bool {
        true
    }
}
