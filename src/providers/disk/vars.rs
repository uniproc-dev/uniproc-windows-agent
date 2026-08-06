use windows::core::GUID;

use crate::etw::vars::guid;

pub const DISK_IO_TASK_GUID: GUID = guid!("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c");

pub const OPCODE_DISK_READ: u8 = 10;
pub const OPCODE_DISK_WRITE: u8 = 11;
pub const OPCODE_DISK_COMPLETE: u8 = 14;
