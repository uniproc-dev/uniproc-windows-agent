/// NTSTATUS STATUS_INFO_LENGTH_MISMATCH: buffer too small, resize and retry.
pub const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004_u32 as i32;

/// Initial buffer for NtQuerySystemInformation; grows on demand.
pub const INITIAL_BUFFER_SIZE: usize = 1024 * 1024;

/// Well-known kernel pseudo-process ids.
pub const IDLE_PROCESS_PID: u32 = 0;
pub const SYSTEM_PROCESS_PID: u32 = 4;
