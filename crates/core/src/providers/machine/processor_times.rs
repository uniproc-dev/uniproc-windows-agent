use anyhow::{Result, bail};
use ntapi::ntexapi::{
    NtQuerySystemInformationEx, SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION,
    SystemProcessorPerformanceInformation,
};
use windows::Win32::GetActiveProcessorGroupCount;

use crate::aligned::AlignedBuf;

const PROCESSORS_PER_GROUP: usize = 64;

/// Sums over every logical processor in every group, 100 ns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessorTimes {
    pub idle: u64,
    pub kernel: u64,
    pub user: u64,
    pub dpc: u64,
    pub interrupt: u64,
}

impl ProcessorTimes {
    fn add(&mut self, entry: &SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) {
        let quad = |v: &ntapi::winapi::shared::ntdef::LARGE_INTEGER| unsafe { *v.QuadPart() } as u64;
        self.idle = self.idle.wrapping_add(quad(&entry.IdleTime));
        self.kernel = self.kernel.wrapping_add(quad(&entry.KernelTime));
        self.user = self.user.wrapping_add(quad(&entry.UserTime));
        self.dpc = self.dpc.wrapping_add(quad(&entry.DpcTime));
        self.interrupt = self.interrupt.wrapping_add(quad(&entry.InterruptTime));
    }
}

/// The processor times of every group; one group answers per call.
pub fn read_totals() -> Result<ProcessorTimes> {
    let entry_size = size_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>();
    let mut buf = AlignedBuf::zeroed(entry_size * PROCESSORS_PER_GROUP);
    let mut totals = ProcessorTimes::default();
    let groups = unsafe { GetActiveProcessorGroupCount() }.max(1);

    for group in 0..groups {
        let mut group = group;
        let mut returned = 0u32;
        let status = unsafe {
            NtQuerySystemInformationEx(
                SystemProcessorPerformanceInformation,
                (&mut group as *mut u16).cast(),
                size_of::<u16>() as u32,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut returned,
            )
        };
        if status < 0 {
            bail!("NtQuerySystemInformationEx(processor performance, group {group}) failed: {status:#x}");
        }
        for i in 0..returned as usize / entry_size {
            let entry = unsafe {
                buf.as_ptr()
                    .add(i * entry_size)
                    .cast::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>()
                    .read_unaligned()
            };
            totals.add(&entry);
        }
    }
    Ok(totals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_processor_is_counted_and_idle_is_part_of_kernel() {
        let first = read_totals().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let second = read_totals().unwrap();
        assert!(second.kernel >= first.kernel && second.user >= first.user);
        assert!(second.idle <= second.kernel, "kernel time includes idle time");

        let processors = std::thread::available_parallelism().unwrap().get() as u64;
        let elapsed = (second.kernel + second.user) - (first.kernel + first.user);
        assert!(
            elapsed >= processors * 50 * 10_000 / 2,
            "{elapsed} over 50 ms for {processors} processors"
        );
    }
}
