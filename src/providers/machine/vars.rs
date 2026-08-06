use std::time::Duration;

use windows::core::{PCWSTR, w};

/// Delay between the two PDH collects needed for a rate counter.
pub const PDH_COLLECT_DELAY: Duration = Duration::from_millis(50);

pub const PDH_PROCESSOR_PERFORMANCE: PCWSTR =
    w!("\\Processor Information(_Total)\\% Processor Performance");
