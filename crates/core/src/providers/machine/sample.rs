use ntapi::ntpoapi::PROCESSOR_POWER_INFORMATION;
use windows::Win32::{
    CallNtPowerInformation, GlobalMemoryStatusEx, MEMORYSTATUSEX, PDH_FMT_COUNTERVALUE,
    PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PdhAddEnglishCounterW, PdhCloseQuery,
    PdhCollectQueryData, PdhGetFormattedCounterValue, PdhOpenQueryW, ProcessorInformation,
    STATUS_SUCCESS,
};
use windows::core::PCWSTR;

use crate::providers::machine::vars::{PDH_CSTATUS_VALID_DATA, PDH_PROCESSOR_PERFORMANCE};
use crate::sample::MachineMemory;

pub struct PdhProcessorPerformance {
    query: PDH_HQUERY,
    counter: PDH_HCOUNTER,
}

impl PdhProcessorPerformance {
    pub fn open() -> Option<Self> {
        unsafe {
            let mut query = PDH_HQUERY::default();
            if PdhOpenQueryW(PCWSTR::null(), 0, &mut query).0 != 0 {
                return None;
            }

            let mut counter = PDH_HCOUNTER::default();
            if PdhAddEnglishCounterW(query, PDH_PROCESSOR_PERFORMANCE, 0, &mut counter).0 != 0 {
                let _ = PdhCloseQuery(query);
                return None;
            }

            // Prime the rate counter; the first formatted value is garbage.
            let _ = PdhCollectQueryData(query);
            Some(Self { query, counter })
        }
    }

    pub fn sample(&mut self) -> Option<f64> {
        unsafe {
            if PdhCollectQueryData(self.query).0 != 0 {
                return None;
            }

            let mut value = PDH_FMT_COUNTERVALUE::default();
            if PdhGetFormattedCounterValue(self.counter, PDH_FMT_DOUBLE, None, &mut value).0 != 0 {
                return None;
            }
            if value.CStatus != PDH_CSTATUS_VALID_DATA {
                return None;
            }

            Some(value.Anonymous.doubleValue.max(0.0))
        }
    }
}

impl Drop for PdhProcessorPerformance {
    fn drop(&mut self) {
        let _ = unsafe { PdhCloseQuery(self.query) };
    }
}

/// The fastest processor's rated clock and the clock they run at now.
pub fn cpu_frequency_mhz(
    pdh: Option<&mut PdhProcessorPerformance>,
    info: &mut Vec<PROCESSOR_POWER_INFORMATION>,
) -> (u32, u32) {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    info.clear();
    info.resize(cpu_count, unsafe { std::mem::zeroed() });

    let status = unsafe {
        CallNtPowerInformation(
            ProcessorInformation,
            None,
            0,
            Some(info.as_mut_ptr().cast()),
            (std::mem::size_of::<PROCESSOR_POWER_INFORMATION>() * info.len()) as u32,
        )
    };

    if status != STATUS_SUCCESS.0 || info.is_empty() {
        return (0, 0);
    }

    let max_mhz = info.iter().map(|v| v.MaxMhz).max().unwrap_or(0);
    let current_avg_mhz = (info.iter().map(|v| v.CurrentMhz as u64).sum::<u64>() / info.len() as u64) as u32;
    let current_mhz = pdh
        .and_then(PdhProcessorPerformance::sample)
        .map(|percent| ((max_mhz as f64) * (percent / 100.0)).round() as u32)
        .unwrap_or(current_avg_mhz);

    (max_mhz, current_mhz)
}

pub fn physical_memory() -> Option<MachineMemory> {
    let mut mem = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    let read = unsafe { GlobalMemoryStatusEx(&mut mem) }.as_bool();
    read.then_some(MachineMemory {
        total_physical: mem.ullTotalPhys.0,
        available_physical: mem.ullAvailPhys.0,
    })
}
