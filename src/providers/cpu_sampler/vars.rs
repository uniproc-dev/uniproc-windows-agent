use windows::core::GUID;

use crate::etw::vars::guid;

pub const PERF_INFO_TASK_GUID: GUID = guid!("CE1DBFB4-137E-4DA6-87B0-3F59AA102CBC");

pub const OPCODE_SAMPLED_PROFILE: u8 = 46;

pub const FLUSH_ENTRIES: usize = 128;
pub const FLUSH_EVENTS: usize = 512;
pub const FLUSH_AGE: std::time::Duration = std::time::Duration::from_millis(100);
