use windows::Win32::Foundation::{FILETIME, STATUS_SUCCESS};
use windows::Win32::System::Performance::{
    PDH_CSTATUS_VALID_DATA, PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY,
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue,
    PdhOpenQueryW,
};
use windows::Win32::System::Power::{
    CallNtPowerInformation, PROCESSOR_POWER_INFORMATION, ProcessorInformation,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::GetSystemTimes;

use crate::providers::machine::vars::{PDH_COLLECT_DELAY, PDH_PROCESSOR_PERFORMANCE};
use crate::state::events::MachineSnapshot;

#[derive(Clone, Copy)]
pub struct CpuTimes {
    idle: u64,
    kernel: u64,
    user: u64,
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sample_cpu_percent(prev: &mut Option<CpuTimes>) -> f32 {
    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    if unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) }.is_err() {
        return 0.0;
    }

    let current = CpuTimes {
        idle: filetime_to_u64(idle),
        kernel: filetime_to_u64(kernel),
        user: filetime_to_u64(user),
    };

    let percent = if let Some(last) = *prev {
        let idle_delta = current.idle.saturating_sub(last.idle);
        let kernel_delta = current.kernel.saturating_sub(last.kernel);
        let user_delta = current.user.saturating_sub(last.user);
        let total_delta = kernel_delta.saturating_add(user_delta);

        if total_delta == 0 {
            0.0
        } else {
            ((total_delta.saturating_sub(idle_delta)) as f64 * 100.0 / total_delta as f64)
                .clamp(0.0, 100.0) as f32
        }
    } else {
        0.0
    };

    *prev = Some(current);
    percent
}

fn sample_processor_performance_percent() -> Option<f64> {
    let mut query = PDH_HQUERY::default();
    if unsafe { PdhOpenQueryW(None, 0, &mut query) } != 0 {
        return None;
    }

    let mut counter = PDH_HCOUNTER::default();
    let add_result = unsafe { PdhAddEnglishCounterW(query, PDH_PROCESSOR_PERFORMANCE, 0, &mut counter) };
    if add_result != 0 {
        let _ = unsafe { PdhCloseQuery(query) };
        return None;
    }

    let _ = unsafe { PdhCollectQueryData(query) };
    // Two PDH collects need a delay between them; fine on the poller thread.
    std::thread::sleep(PDH_COLLECT_DELAY);
    if unsafe { PdhCollectQueryData(query) } != 0 {
        let _ = unsafe { PdhCloseQuery(query) };
        return None;
    }

    let mut value = PDH_FMT_COUNTERVALUE::default();
    let format_result =
        unsafe { PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut value) };
    let _ = unsafe { PdhCloseQuery(query) };
    if format_result != 0 {
        return None;
    }
    if value.CStatus != PDH_CSTATUS_VALID_DATA {
        return None;
    }

    Some(unsafe { value.Anonymous.doubleValue }.max(0.0))
}

fn sample_cpu_frequency_mhz() -> (u64, u64) {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut info = vec![PROCESSOR_POWER_INFORMATION::default(); cpu_count];

    let status = unsafe {
        CallNtPowerInformation(
            ProcessorInformation,
            None,
            0,
            Some(info.as_mut_ptr().cast()),
            (std::mem::size_of::<PROCESSOR_POWER_INFORMATION>() * info.len()) as u32,
        )
    };

    if status != STATUS_SUCCESS || info.is_empty() {
        return (0, 0);
    }

    let max_mhz = info.iter().map(|v| v.MaxMhz as u64).max().unwrap_or(0);
    let current_avg_mhz = info.iter().map(|v| v.CurrentMhz as u64).sum::<u64>() / info.len() as u64;
    let current_mhz = sample_processor_performance_percent()
        .map(|percent| ((max_mhz as f64) * (percent / 100.0)).round() as u64)
        .unwrap_or(current_avg_mhz);

    (max_mhz, current_mhz)
}

pub fn sample_machine(prev_cpu_times: &mut Option<CpuTimes>) -> MachineSnapshot {
    let mut snap = MachineSnapshot {
        cpu_percent: sample_cpu_percent(prev_cpu_times),
        timestamp_ms: now_ms(),
        ..Default::default()
    };

    let (cpu_max_mhz, cpu_current_mhz) = sample_cpu_frequency_mhz();
    snap.cpu_max_mhz = cpu_max_mhz;
    snap.cpu_current_mhz = cpu_current_mhz;

    let mut mem = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut mem) }.is_ok() {
        snap.total_physical_kb = mem.ullTotalPhys / 1024;
        snap.available_physical_kb = mem.ullAvailPhys / 1024;
        snap.used_physical_kb = (mem.ullTotalPhys - mem.ullAvailPhys) / 1024;
    }

    snap
}
