//! Reads the events that tell a process's start and exit, by their fields'
//! names, so a newer version of an event reads as well.

use smol_str::SmolStr;
use uniproc_etw::Event;
use windows_core::GUID;

use super::ProcessExited;
use super::assemble::{Created, Ended, Launched, Raw, Scheduled};
use crate::etw::vars::guid;

pub(crate) const KERNEL_PROCESS: GUID = guid!("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");
/// The kernel's own Process events, under EVENT_TRACE_FLAG_PROCESS.
pub(crate) const PROCESS: GUID = guid!("3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C");
pub(crate) const TASK_SCHEDULER: GUID = guid!("DE7B24EA-73C8-4A09-985D-5BDADCFA9017");

/// Kernel-Process's keyword for process starts and exits.
pub(crate) const KERNEL_PROCESS_KEYWORD: u64 = 0x10;

const KERNEL_PROCESS_START: u16 = 1;
const KERNEL_PROCESS_STOP: u16 = 2;
const PROCESS_START_OPCODE: u8 = 1;
const TASK_PROCESS_CREATED: u16 = 129;

/// Whether `record` is one of the events read here, before it is copied.
pub(crate) fn wanted(event: &Event<'_>) -> bool {
    match event.provider() {
        provider if provider == KERNEL_PROCESS.to_u128() => matches!(event.id(), KERNEL_PROCESS_START | KERNEL_PROCESS_STOP),
        provider if provider == PROCESS.to_u128() => event.opcode() == PROCESS_START_OPCODE,
        provider if provider == TASK_SCHEDULER.to_u128() => event.id() == TASK_PROCESS_CREATED,
        _ => false,
    }
}

/// What `event` tells; `working_directory` reads a process that just
/// started.
pub(crate) fn decode(event: &Event<'_>, working_directory: impl FnOnce(u32) -> SmolStr) -> Option<Raw> {
    let event = Fields(event);
    let time = event.0.timestamp() as u64;
    let (provider, id, opcode) = (event.0.provider(), event.0.id(), event.0.opcode());
    match provider {
        provider if provider == KERNEL_PROCESS.to_u128() && id == KERNEL_PROCESS_START => {
            let pid = event.number("ProcessID")? as u32;
            Some(Raw::Created(Created {
                pid,
                sequence_number: event.number("ProcessSequenceNumber").filter(|&n| n != 0)?,
                time: event.number("CreateTime").unwrap_or(time),
                parent_pid: event.number("ParentProcessID").unwrap_or(0) as u32,
                parent_sequence_number: event.number("ParentProcessSequenceNumber").unwrap_or(0),
                session_id: event.number("SessionID").unwrap_or(0) as u32,
                image: event.text("ImageName"),
                elevated: event.number("ProcessTokenIsElevated").map(|elevated| elevated != 0),
                package_full_name: event.text("PackageFullName"),
                working_directory: working_directory(pid),
            }))
        }
        provider if provider == KERNEL_PROCESS.to_u128() && id == KERNEL_PROCESS_STOP => Some(Raw::Ended(Ended {
            pid: event.number("ProcessID")? as u32,
            sequence_number: event.number("ProcessSequenceNumber").filter(|&n| n != 0)?,
            time: event.number("ExitTime").unwrap_or(time),
            exited: ProcessExited {
                image_path: SmolStr::default(),
                image_name: event.ansi("ImageName"),
                start_time: event.number("CreateTime").unwrap_or(0),
                exit_code: event.number("ExitCode").unwrap_or(0) as u32,
                cpu_cycles: event.number("CPUCycleCount").unwrap_or(0),
                io_read_ops: event.number("ReadOperationCount").unwrap_or(0),
                io_write_ops: event.number("WriteOperationCount").unwrap_or(0),
                io_read_bytes: event.number("ReadTransferKiloBytes").unwrap_or(0) * 1024,
                io_write_bytes: event.number("WriteTransferKiloBytes").unwrap_or(0) * 1024,
                peak_commit: event.number("CommitPeak").unwrap_or(0),
                handles: event.number("HandleCount").unwrap_or(0) as u32,
                hard_faults: event.number("HardFaultCount").unwrap_or(0) as u32,
            },
        })),
        provider if provider == PROCESS.to_u128() && opcode == PROCESS_START_OPCODE => Some(Raw::Launched(Launched {
            pid: event.number("ProcessId")? as u32,
            time,
            sid: event.sid("UserSID"),
            command_line: event.text("CommandLine"),
        })),
        provider if provider == TASK_SCHEDULER.to_u128() && id == TASK_PROCESS_CREATED => Some(Raw::Scheduled(Scheduled {
            pid: event.number("ProcessID")? as u32,
            time,
            task: event.text("TaskName"),
        })),
        _ => None,
    }
}

/// An event's fields as the process events keep them: a missing string or
/// SID is empty.
struct Fields<'a, 'e>(&'a Event<'e>);

impl Fields<'_, '_> {
    fn number(&self, name: &str) -> Option<u64> {
        self.0.number(name)
    }

    fn text(&self, name: &str) -> SmolStr {
        self.0.text(name).map(SmolStr::from).unwrap_or_default()
    }

    fn ansi(&self, name: &str) -> SmolStr {
        self.0.ansi(name).map(SmolStr::from).unwrap_or_default()
    }

    /// The classic Process event's UserSID is a TOKEN_USER.
    fn sid(&self, name: &str) -> Vec<u8> {
        self.0.wbem_sid(name).unwrap_or_default()
    }
}
