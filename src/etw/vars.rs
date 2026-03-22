use windows::core::GUID;

macro_rules! guid {
    ($s:literal) => {{
        const BYTES: &[u8] = $s.as_bytes();
        const fn hex(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex char"),
            }
        }
        const fn byte(hi: u8, lo: u8) -> u8 {
            hex(hi) << 4 | hex(lo)
        }
        GUID::from_values(
            u32::from_be_bytes([
                byte(BYTES[0], BYTES[1]),
                byte(BYTES[2], BYTES[3]),
                byte(BYTES[4], BYTES[5]),
                byte(BYTES[6], BYTES[7]),
            ]),
            u16::from_be_bytes([byte(BYTES[9], BYTES[10]), byte(BYTES[11], BYTES[12])]),
            u16::from_be_bytes([byte(BYTES[14], BYTES[15]), byte(BYTES[16], BYTES[17])]),
            [
                byte(BYTES[19], BYTES[20]),
                byte(BYTES[21], BYTES[22]),
                byte(BYTES[24], BYTES[25]),
                byte(BYTES[26], BYTES[27]),
                byte(BYTES[28], BYTES[29]),
                byte(BYTES[30], BYTES[31]),
                byte(BYTES[32], BYTES[33]),
                byte(BYTES[34], BYTES[35]),
            ],
        )
    }};
}
/// Microsoft-Windows-Kernel-Process  (modern, manifest-based)
pub const KERNEL_PROCESS_PROVIDER: GUID = guid!("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

/// NT Kernel Logger — Disk I/O  (classic GUID, DiskIo_TypeGroup*)
pub const KERNEL_DISK_PROVIDER: GUID = guid!("3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C");

/// NT Kernel Logger — Network  (classic GUID, TcpIp_TypeGroup* / UdpIp_TypeGroup*)
pub const KERNEL_NETWORK_PROVIDER: GUID = guid!("9A280AC0-C8E0-11D1-84E2-00C04FB998A2");

pub const KERNEL_PROCESS_PROVIDER_CLASSIC: GUID = guid!("3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C");

//https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs#L3014
pub const EVENT_TRACE_TASK_GUID: GUID = guid!("68fdd900-4a3e-11d1-84f4-0000f80464e3");
pub const PROCESS_TASK_GUID: GUID = guid!("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c");
pub const THREAD_TASK_GUID: GUID = guid!("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c");
pub const DISK_IO_TASK_GUID: GUID = guid!("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c");
pub const REGISTRY_TASK_GUID: GUID = guid!("ae53722e-c863-11d2-8659-00c04fa321a1");
pub const SPLIT_IO_TASK_GUID: GUID = guid!("d837ca92-12b9-44a5-ad6a-3a65b3578aa8");
pub const FILE_IO_TASK_GUID: GUID = guid!("90cbdc39-4a3e-11d1-84f4-0000f80464e3");
pub const TCPIP_TASK_GUID: GUID = guid!("9a280ac0-c8e0-11d1-84e2-00c04fb998a2");
pub const UDPIP_TASK_GUID: GUID = guid!("bf3a50c5-a9c9-4988-a005-2df0b7c80f80");
pub const IMAGE_TASK_GUID: GUID = guid!("2cb15d1d-5fc1-11d2-abe1-00a0c911f518");
pub const MEMORY_TASK_GUID: GUID = guid!("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c");
pub const PERF_INFO_TASK_GUID: GUID = guid!("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc");
pub const STACK_WALK_TASK_GUID: GUID = guid!("def2fe46-7bd6-4b80-bd94-f57fe20d0ce3");
pub const ALPC_TASK_GUID: GUID = guid!("45d8cccd-539f-4b72-a8b7-5c6831426009");
pub const LOST_EVENT_TASK_GUID: GUID = guid!("6a399ae0-4bc6-4de9-870b-3657f8947e7e");
pub const SYSTEM_CONFIG_TASK_GUID: GUID = guid!("01853a65-418f-4f36-aefc-dc0f1d2fd235");
pub const VIRTUAL_ALLOC_TASK_GUID: GUID = guid!("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c");
pub const OBJECT_TASK_GUID: GUID = guid!("89497f50-effe-4440-8cf2-ce6b1cdcaca7");
pub const LBR_TASK_GUID: GUID = guid!("99134383-5248-43fc-834b-529454e75df3");

// Classic opcode constants not exported by the windows crate
pub const EVENT_TRACE_TYPE_DISK_READ: u8 = 10;
pub const EVENT_TRACE_TYPE_DISK_WRITE: u8 = 11;

// TcpIp opcodes
pub const TCPIP_SEND: u8 = 10;
pub const TCPIP_RECEIVE: u8 = 11;
pub const TCPIP_CONNECT: u8 = 12;
pub const TCPIP_ACCEPT: u8 = 15;
pub const UDPIP_SEND: u8 = 26;
pub const UDPIP_RECEIVE: u8 = 27;
