use std::collections::HashMap;

use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub struct PrevEntry {
    pub kernel: u64,
    pub user: u64,
}

pub unsafe fn sample(
    pid: u32,
    prev: &mut HashMap<u32, PrevEntry>,
    elapsed_ns: u64,
    num_cores: u64,
) -> f64 {
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return 0.0,
    };

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    let _ = unsafe { CloseHandle(handle) };

    if ok.is_err() {
        return 0.0;
    }

    let k = (kernel.dwHighDateTime as u64) << 32 | kernel.dwLowDateTime as u64;
    let u = (user.dwHighDateTime as u64) << 32 | user.dwLowDateTime as u64;
    let total = k + u;

    let delta = match prev.get(&pid) {
        Some(e) => total.saturating_sub(e.kernel + e.user),
        None => {
            prev.insert(pid, PrevEntry { kernel: k, user: u });
            return 0.0;
        }
    };

    prev.insert(pid, PrevEntry { kernel: k, user: u });

    (delta as f64 / (elapsed_ns / 100) as f64 * 100.0 / num_cores as f64).min(100.0)
}
