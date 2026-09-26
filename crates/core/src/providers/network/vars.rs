use windows::core::GUID;

use crate::etw::vars::guid;

pub const TCPIP_TASK_GUID: GUID = guid!("9a280ac0-c8e0-11d1-84e2-00c04fb998a2");
pub const UDPIP_TASK_GUID: GUID = guid!("bf3a50c5-a9c9-4988-a005-2df0b7c80f80");

// Opcodes are only meaningful per provider GUID: 10 on TCPIP_TASK_GUID is
// TCP SendIPv4, on UDPIP_TASK_GUID it is UDP SendIPv4.
pub const TCPIP_SEND_V4: u8 = 10;
pub const TCPIP_RECEIVE_V4: u8 = 11;
pub const TCPIP_CONNECT_V4: u8 = 12;
pub const TCPIP_ACCEPT_V4: u8 = 15;
pub const TCPIP_SEND_V6: u8 = 26;
pub const TCPIP_RECEIVE_V6: u8 = 27;
pub const TCPIP_CONNECT_V6: u8 = 28;
pub const TCPIP_ACCEPT_V6: u8 = 31;

pub const UDPIP_SEND_V4: u8 = 10;
pub const UDPIP_RECEIVE_V4: u8 = 11;
pub const UDPIP_SEND_V6: u8 = 26;
pub const UDPIP_RECEIVE_V6: u8 = 27;
