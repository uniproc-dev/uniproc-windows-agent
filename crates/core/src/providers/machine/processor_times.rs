use anyhow::{Result, bail};
use ntapi::ntexapi::{
    NtQuerySystemInformationEx, SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION,
    SystemProcessorPerformanceInformation,
};
use windows::Win32::GetActiveProcessorGroupCount;

use crate::aligned::AlignedBuf;
use crate::sample::MachineProcessor;

const PROCESSORS_PER_GROUP: usize = 64;
const ENTRY_SIZE: usize = size_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>();

/// Every logical processor's times, read into buffers kept across reads.
pub struct ProcessorTimes {
    buf: AlignedBuf,
    processors: Vec<MachineProcessor>,
}

impl Default for ProcessorTimes {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessorTimes {
    pub fn new() -> Self {
        Self {
            buf: AlignedBuf::zeroed(ENTRY_SIZE * PROCESSORS_PER_GROUP),
            processors: Vec::new(),
        }
    }

    /// Group 0 first, in processor order within a group; one group answers
    /// per call.
    pub fn read(&mut self) -> Result<&[MachineProcessor]> {
        self.processors.clear();
        let groups = unsafe { GetActiveProcessorGroupCount() }.max(1);
        for group in 0..groups {
            let mut group = group;
            let mut returned = 0u32;
            let status = unsafe {
                NtQuerySystemInformationEx(
                    SystemProcessorPerformanceInformation,
                    (&mut group as *mut u16).cast(),
                    size_of::<u16>() as u32,
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len() as u32,
                    &mut returned,
                )
            };
            if status < 0 {
                bail!("NtQuerySystemInformationEx(processor performance, group {group}) failed: {status:#x}");
            }
            let quad = |v: &ntapi::winapi::shared::ntdef::LARGE_INTEGER| unsafe { *v.QuadPart() } as u64;
            for i in 0..returned as usize / ENTRY_SIZE {
                let entry = unsafe {
                    self.buf
                        .as_ptr()
                        .add(i * ENTRY_SIZE)
                        .cast::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>()
                        .read_unaligned()
                };
                self.processors.push(MachineProcessor {
                    idle_time: quad(&entry.IdleTime),
                    kernel_time: quad(&entry.KernelTime),
                    user_time: quad(&entry.UserTime),
                    interrupt_time: quad(&entry.InterruptTime),
                    dpc_time: quad(&entry.DpcTime),
                });
            }
        }
        Ok(&self.processors)
    }
}

/// The processors' times summed.
pub fn total(processors: &[MachineProcessor]) -> MachineProcessor {
    processors.iter().fold(MachineProcessor::default(), |sum, p| MachineProcessor {
        idle_time: sum.idle_time.wrapping_add(p.idle_time),
        kernel_time: sum.kernel_time.wrapping_add(p.kernel_time),
        user_time: sum.user_time.wrapping_add(p.user_time),
        interrupt_time: sum.interrupt_time.wrapping_add(p.interrupt_time),
        dpc_time: sum.dpc_time.wrapping_add(p.dpc_time),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_processor_is_counted_and_idle_is_part_of_kernel() {
        let mut times = ProcessorTimes::new();
        let first = total(times.read().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(50));
        let processors = times.read().unwrap();
        assert_eq!(processors.len(), std::thread::available_parallelism().unwrap().get());
        assert!(processors.iter().all(|p| p.idle_time <= p.kernel_time));
        let second = total(processors);
        assert!(second.kernel_time >= first.kernel_time && second.user_time >= first.user_time);

        let count = processors.len() as u64;
        let elapsed = (second.kernel_time + second.user_time) - (first.kernel_time + first.user_time);
        assert!(
            elapsed >= count * 50 * 10_000 / 2,
            "{elapsed} over 50 ms for {count} processors"
        );
    }
}
