//! Reads the events that tell a process's start and exit, by their fields'
//! names, so a newer version of an event reads as well.

use smol_str::SmolStr;
use windows::Win32::{
    EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR, TdhGetProperty, TdhGetPropertySize,
};
use windows::core::GUID;

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
pub(crate) fn wanted(record: &EVENT_RECORD) -> bool {
    let descriptor = &record.EventHeader.EventDescriptor;
    match record.EventHeader.ProviderId {
        KERNEL_PROCESS => matches!(descriptor.Id, KERNEL_PROCESS_START | KERNEL_PROCESS_STOP),
        PROCESS => descriptor.Opcode == PROCESS_START_OPCODE,
        TASK_SCHEDULER => descriptor.Id == TASK_PROCESS_CREATED,
        _ => false,
    }
}

/// An event copied out of the ETW callback, read on another thread.
pub(crate) struct Record {
    record: EVENT_RECORD,
    data: Vec<u8>,
}

unsafe impl Send for Record {}

impl Record {
    pub fn copy(record: &EVENT_RECORD, data: &[u8]) -> Self {
        let mut record = *record;
        record.UserData = std::ptr::null_mut();
        record.UserDataLength = 0;
        record.ExtendedData = std::ptr::null_mut();
        record.ExtendedDataCount = 0;
        record.UserContext = std::ptr::null_mut();
        Self {
            record,
            data: data.to_vec(),
        }
    }

    fn record(&self) -> EVENT_RECORD {
        let mut record = self.record;
        record.UserData = self.data.as_ptr() as *mut _;
        record.UserDataLength = self.data.len() as u16;
        record
    }
}

/// What `record` tells; `working_directory` reads a process that just
/// started.
pub(crate) fn decode(record: &Record, working_directory: impl FnOnce(u32) -> SmolStr) -> Option<Raw> {
    let event = Fields(record.record());
    let header = &event.0.EventHeader;
    let descriptor = &header.EventDescriptor;
    let time = header.TimeStamp as u64;
    match header.ProviderId {
        KERNEL_PROCESS if descriptor.Id == KERNEL_PROCESS_START => {
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
        KERNEL_PROCESS if descriptor.Id == KERNEL_PROCESS_STOP => Some(Raw::Ended(Ended {
            pid: event.number("ProcessID")? as u32,
            sequence_number: event.number("ProcessSequenceNumber").filter(|&n| n != 0)?,
            time: event.number("ExitTime").unwrap_or(time),
            exited: ProcessExited {
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
        PROCESS if descriptor.Opcode == PROCESS_START_OPCODE => Some(Raw::Launched(Launched {
            pid: event.number("ProcessId")? as u32,
            time,
            sid: event.sid("UserSID"),
            command_line: event.text("CommandLine"),
        })),
        TASK_SCHEDULER if descriptor.Id == TASK_PROCESS_CREATED => Some(Raw::Scheduled(Scheduled {
            pid: event.number("ProcessID")? as u32,
            time,
            task: event.text("TaskName"),
        })),
        _ => None,
    }
}

struct Fields(EVENT_RECORD);

impl Fields {
    fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let descriptor = [PROPERTY_DATA_DESCRIPTOR {
            PropertyName: name.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        }];
        let mut size = 0u32;
        if unsafe { TdhGetPropertySize(&self.0, None, &descriptor, &mut size) }.0 != 0 {
            return None;
        }
        let mut bytes = vec![0u8; size as usize];
        if unsafe { TdhGetProperty(&self.0, None, &descriptor, size, bytes.as_mut_ptr()) }.0 != 0 {
            return None;
        }
        Some(bytes)
    }

    fn number(&self, name: &str) -> Option<u64> {
        let bytes = self.bytes(name)?;
        let mut le = [0u8; 8];
        let len = bytes.len().min(8);
        le[..len].copy_from_slice(&bytes[..len]);
        Some(u64::from_le_bytes(le))
    }

    fn text(&self, name: &str) -> SmolStr {
        let Some(bytes) = self.bytes(name) else {
            return SmolStr::default();
        };
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|&unit| unit != 0)
            .collect();
        String::from_utf16_lossy(&units).into()
    }

    /// The SID of a kernel event's TOKEN_USER: the SID follows the
    /// structure's pointer and attributes.
    fn sid(&self, name: &str) -> Vec<u8> {
        let Some(bytes) = self.bytes(name) else {
            return Vec::new();
        };
        let pointer = if self.0.EventHeader.Flags as u32 & EVENT_HEADER_FLAG_64_BIT_HEADER as u32 != 0 { 8 } else { 4 };
        match bytes.get(2 * pointer..) {
            Some(sid) if sid.first() == Some(&1) => sid.to_vec(),
            _ => Vec::new(),
        }
    }
}
