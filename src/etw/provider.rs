use std::ffi::OsString;
use std::io::Cursor;
use std::os::windows::ffi::OsStringExt;
use binrw::{BinRead, NullString, NullWideString};
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Etw::*;
use crate::etw::signatures::defines::ProcessStartV4Header;

pub const KERNEL_PROCESS_PROVIDER: windows::core::GUID = windows::core::GUID::from_values(
    0x22FB2CD6,
    0x0E7B,
    0x422B,
    [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub event_type: ProcessEventType,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub session_id: u32,
    pub image_name: String,
    pub command_line: String
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProcessEventType {
    Start,
    Stop,
    ImageLoad,
    ProcessRundown,
    Unknown(u16),
}

impl std::fmt::Display for ProcessEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            _ => write!(f, "UNKNOWN"),
        }
    }
}

impl From<u16> for ProcessEventType {
    fn from(id: u16) -> Self {
        match id {
            1 => Self::Start,
            2 => Self::Stop,
            5 => Self::ImageLoad,
            15 => Self::ProcessRundown,
            _ => Self::Unknown(id),
        }
    }
}

pub unsafe fn to_user_data(event_record: &EVENT_RECORD) -> &[u8] {
    std::slice::from_raw_parts(
        event_record.UserData as *const u8,
        event_record.UserDataLength as usize,
    )
}

pub unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }

    let record = &*event_record;
    let event_id = record.EventHeader.EventDescriptor.Id;

    let event_type = ProcessEventType::from(event_id);

    let process_start = if let ProcessEventType::Start = event_type {

        let data = to_user_data(record);

        let mut cursor = Cursor::new(data);

        ProcessStartV4Header::read(&mut cursor).ok()
    }
    else {
        None
    };

    match event_type {
        ProcessEventType::Start => {
            if let Some(process_start) = process_start {
                println!("process start name: {}", process_start.image_name);
            }
        },
        ProcessEventType::ProcessRundown => {
            println!("rundown");
        }
        ProcessEventType::Stop => handle_process_event(record, ProcessEventType::Stop),
        ProcessEventType::ImageLoad => handle_image_load(record),
        ProcessEventType::Unknown(_) => {}
    }

}

#[derive(BinRead, Debug)]
#[br(little)]
struct ProcessEventData {
    process_id: u32,
    parent_process_id: u32,
    session_id: u32,
}


unsafe fn handle_process_event(record: &EVENT_RECORD, event_type: ProcessEventType) {

    let data = std::slice::from_raw_parts(
        record.UserData as *const u8,
        record.UserDataLength as usize,
    );

    let mut cursor = Cursor::new(data);
    
    let Ok(header) = ProcessEventData::read(&mut cursor) else {
        warn!("Failed to read process event header");
        return;
    };
    
    match event_type {
        ProcessEventType::Start => {
        }

        ProcessEventType::Stop => {

            let ev = ProcessEvent {
                event_type,
                process_id: header.process_id,
                parent_process_id: header.parent_process_id,
                session_id: header.session_id,
                image_name: String::new(),
                command_line: String::new(),
            };

            info!(
                "[{}] pid={} ppid={} session={}",
                event_type,
                ev.process_id,
                ev.parent_process_id,
                ev.session_id,
            );
        }

        _ => {}
    }
}

unsafe fn handle_image_load(record: &EVENT_RECORD) {
    if record.UserDataLength < 8 {
        return;
    }
    let data = std::slice::from_raw_parts(
        record.UserData as *const u8,
        record.UserDataLength as usize,
    );
    let (image_path, _) = parse_wchar_strings(data, 8);
    debug!(
        "[IMAGE LOAD] pid={} image=\"{image_path}\"",
        record.EventHeader.ProcessId
    );
}

fn parse_wchar_strings(data: &[u8], offset: usize) -> (String, String) {
    if offset >= data.len() {
        return (String::new(), String::new());
    }

    let wchar_data = &data[offset..];

    let wchars: Vec<u16> = wchar_data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();

    let first_end = wchars.iter().position(|&c| c == 0).unwrap_or(wchars.len());
    let first = OsString::from_wide(&wchars[..first_end])
        .to_string_lossy()
        .into_owned();

    let second_start = first_end + 1;
    let second = if second_start < wchars.len() {
        let second_end = wchars[second_start..]
            .iter()
            .position(|&c| c == 0)
            .map(|p| second_start + p)
            .unwrap_or(wchars.len());
        OsString::from_wide(&wchars[second_start..second_end])
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };

    (first, second)
}