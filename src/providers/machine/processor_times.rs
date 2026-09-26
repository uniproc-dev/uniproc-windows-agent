use anyhow::{Result, bail};
use ntapi::ntexapi::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;
use windows::Win32::{NtQuerySystemInformation, SystemProcessorPerformanceInformation};

use crate::aligned::AlignedBuf;
use crate::providers::bootstrap::vars::STATUS_INFO_LENGTH_MISMATCH;

const INITIAL_PROCESSOR_SLOTS: usize = 64;

#[derive(Clone, Copy, Default)]
pub struct ProcessorTimes {
    idle: u64,
    kernel: u64,
    user: u64,
    dpc: u64,
    interrupt: u64,
}

#[derive(Clone, Copy, Default)]
pub struct ProcessorBreakdown {
    pub busy_percent: f32,
    pub interrupt_percent: f32,
    pub dpc_percent: f32,
}

fn read_totals() -> Result<ProcessorTimes> {
    let entry_size = size_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>();
    let mut slots = INITIAL_PROCESSOR_SLOTS;

    loop {
        let mut buf = AlignedBuf::zeroed(entry_size * slots);
        let mut return_length = 0u32;

        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessorPerformanceInformation,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                Some(&mut return_length),
            )
        };

        if status.0 == STATUS_INFO_LENGTH_MISMATCH {
            slots = (return_length as usize / entry_size) + 1;
            continue;
        }

        if status.is_err() {
            bail!("NtQuerySystemInformation(processor performance) failed: {status:?}");
        }

        let count = return_length as usize / entry_size;
        let mut totals = ProcessorTimes::default();

        for i in 0..count {
            let entry = unsafe {
                &*(buf.as_ptr().add(i * entry_size) as *const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)
            };

            totals.idle = totals.idle.wrapping_add(unsafe { *entry.IdleTime.QuadPart() } as u64);
            totals.kernel = totals
                .kernel
                .wrapping_add(unsafe { *entry.KernelTime.QuadPart() } as u64);
            totals.user = totals.user.wrapping_add(unsafe { *entry.UserTime.QuadPart() } as u64);
            totals.dpc = totals.dpc.wrapping_add(unsafe { *entry.DpcTime.QuadPart() } as u64);
            totals.interrupt = totals
                .interrupt
                .wrapping_add(unsafe { *entry.InterruptTime.QuadPart() } as u64);
        }

        return Ok(totals);
    }
}

fn breakdown(previous: ProcessorTimes, current: ProcessorTimes) -> Option<ProcessorBreakdown> {
    let idle = current.idle.checked_sub(previous.idle)?;
    let kernel = current.kernel.checked_sub(previous.kernel)?;
    let user = current.user.checked_sub(previous.user)?;
    let dpc = current.dpc.checked_sub(previous.dpc)?;
    let interrupt = current.interrupt.checked_sub(previous.interrupt)?;

    let total = kernel.checked_add(user)? as f64;
    if total <= 0.0 {
        return None;
    }

    let share = |part: u64| ((part as f64 / total) * 100.0).clamp(0.0, 100.0) as f32;

    Some(ProcessorBreakdown {
        busy_percent: share(total as u64 - idle.min(total as u64)),
        interrupt_percent: share(interrupt),
        dpc_percent: share(dpc),
    })
}

pub fn sample_processor_times(previous: &mut Option<ProcessorTimes>) -> ProcessorBreakdown {
    let current = match read_totals() {
        Ok(times) => times,
        Err(err) => {
            tracing::warn!(%err, "could not read processor performance information");
            return ProcessorBreakdown::default();
        }
    };

    let result = previous
        .and_then(|prev| breakdown(prev, current))
        .unwrap_or_default();

    *previous = Some(current);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn times(idle: u64, kernel: u64, user: u64, dpc: u64, interrupt: u64) -> ProcessorTimes {
        ProcessorTimes {
            idle,
            kernel,
            user,
            dpc,
            interrupt,
        }
    }

    #[test]
    fn idle_time_is_part_of_kernel_time() {
        let previous = times(0, 0, 0, 0, 0);
        let current = times(750, 800, 200, 0, 0);

        let out = breakdown(previous, current).expect("a second sample yields a breakdown");
        assert!((out.busy_percent - 25.0).abs() < 0.01);
    }

    #[test]
    fn interrupts_and_dpcs_are_reported_against_the_same_total() {
        let previous = times(0, 0, 0, 0, 0);
        let current = times(0, 800, 200, 50, 100);

        let out = breakdown(previous, current).expect("a second sample yields a breakdown");
        assert!((out.busy_percent - 100.0).abs() < 0.01);
        assert!((out.dpc_percent - 5.0).abs() < 0.01);
        assert!((out.interrupt_percent - 10.0).abs() < 0.01);
    }

    #[test]
    fn the_first_sample_has_nothing_to_compare_against() {
        let previous: Option<ProcessorTimes> = None;
        assert!(
            previous
                .and_then(|prev| breakdown(prev, times(1, 1, 1, 1, 1)))
                .is_none()
        );
    }

    #[test]
    fn counters_going_backwards_yield_nothing() {
        let previous = times(100, 200, 100, 10, 10);
        let current = times(50, 100, 50, 5, 5);

        assert!(breakdown(previous, current).is_none());
    }
}
