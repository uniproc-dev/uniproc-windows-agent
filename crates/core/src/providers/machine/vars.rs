use windows::core::{PCWSTR, w};

pub const PDH_PROCESSOR_PERFORMANCE: PCWSTR =
    w!("\\Processor Information(_Total)\\% Processor Performance");

pub const PDH_CSTATUS_VALID_DATA: u32 = 0;
