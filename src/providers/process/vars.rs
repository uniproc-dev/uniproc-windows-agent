use windows::core::GUID;

use crate::etw::vars::guid;

pub const KERNEL_PROCESS_PROVIDER: GUID = guid!("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

pub const EVENT_ID_PROCESS_START: u16 = 1;
pub const EVENT_ID_PROCESS_STOP: u16 = 2;
pub const EVENT_ID_THREAD_START: u16 = 3;
pub const EVENT_ID_THREAD_STOP: u16 = 4;
