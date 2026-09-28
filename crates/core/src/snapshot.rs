//! Every process on the machine at one moment, from one
//! NtQuerySystemInformation(SystemFullProcessInformation) call.

use std::mem::{offset_of, size_of};

use anyhow::{Result, bail};
use ntapi::ntexapi::{
    NtQuerySystemInformation, SYSTEM_EXTENDED_THREAD_INFORMATION, SYSTEM_PROCESS_INFORMATION,
    SYSTEM_PROCESS_INFORMATION_EXTENSION, SystemFullProcessInformation,
};

use crate::aligned::AlignedBuf;

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const INITIAL_BUFFER_SIZE: usize = 2 * 1024 * 1024;
const HEADROOM: usize = 64 * 1024;

const THREAD_WAITING: u32 = 5;
const WAIT_REASON_SUSPENDED: u32 = 5;

pub const IDLE_PROCESS_PID: u32 = 0;
pub const SYSTEM_PROCESS_PID: u32 = 4;

/// Processes the kernel starts under System that have no image file.
const KERNEL_PSEUDO_PROCESSES: &[&str] = &["Registry", "Memory Compression", "Secure System"];

/// A pseudo-process of the kernel itself: Idle, System, and the few the
/// kernel starts under System with no image on disk. Decided by what the
/// process is, never by whether its image path could be read.
pub fn is_kernel_pseudo_process(pid: u32, parent_pid: u32, image_name: &str) -> bool {
    pid == IDLE_PROCESS_PID
        || pid == SYSTEM_PROCESS_PID
        || (parent_pid == SYSTEM_PROCESS_PID && KERNEL_PSEUDO_PROCESSES.contains(&image_name))
}

/// One process as the kernel counted it. Counters are cumulative and raw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub(crate) offset: usize,
    pub(crate) end: usize,
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    /// 0 only for the Idle process.
    pub sequence_number: u64,
    /// FILETIME.
    pub create_time: u64,
    pub base_priority: i32,
    pub handles: u32,
    pub threads: u32,
    /// Every thread waits with reason Suspended.
    pub suspended: bool,

    pub user_time: u64,
    pub kernel_time: u64,
    pub cycles: u64,

    pub working_set: u64,
    pub peak_working_set: u64,
    pub private_working_set: u64,
    pub commit: u64,
    pub paged_pool: u64,
    pub nonpaged_pool: u64,
    pub page_faults: u32,

    pub io_read_ops: u64,
    pub io_write_ops: u64,
    pub io_other_ops: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub io_other_bytes: u64,

    pub disk_read_ops: u64,
    pub disk_write_ops: u64,
    pub disk_flush_ops: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,

    pub job_object_id: u32,
}

/// The kernel's process list, read into a buffer kept across reads.
pub struct Processes {
    buf: AlignedBuf,
    filled: usize,
    rows: Vec<Row>,
}

impl Default for Processes {
    fn default() -> Self {
        Self::new()
    }
}

impl Processes {
    pub fn new() -> Self {
        Self {
            buf: AlignedBuf::zeroed(0),
            filled: 0,
            rows: Vec::new(),
        }
    }

    /// Reads the list again. Needs an elevated caller.
    #[tracing::instrument(name = "snapshot", level = "debug", skip_all)]
    pub fn read(&mut self) -> Result<()> {
        self.rows.clear();
        self.filled = 0;
        let mut size = self.buf.len().max(INITIAL_BUFFER_SIZE);
        loop {
            if self.buf.len() < size {
                self.buf = AlignedBuf::zeroed(size);
            }
            let mut needed = 0u32;
            let status = unsafe {
                NtQuerySystemInformation(
                    SystemFullProcessInformation,
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len() as u32,
                    &mut needed,
                )
            };
            if status == STATUS_INFO_LENGTH_MISMATCH {
                size = needed as usize + HEADROOM;
                continue;
            }
            if status < 0 {
                bail!("NtQuerySystemInformation(SystemFullProcessInformation) failed: {status:#x}");
            }
            self.filled = (needed as usize).min(self.buf.len());
            break;
        }
        self.parse();
        Ok(())
    }

    /// Ordered by pid.
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr(), self.filled) }
    }

    fn parse(&mut self) {
        let base = self.buf.as_ptr();
        let filled = self.filled;
        let mut offset = 0usize;
        let threads_at = offset_of!(SYSTEM_PROCESS_INFORMATION, Threads);
        while offset + threads_at <= filled {
            let entry = unsafe { base.add(offset).cast::<SYSTEM_PROCESS_INFORMATION>().read_unaligned() };
            let next = entry.NextEntryOffset as usize;
            let end = if next == 0 { filled } else { (offset + next).min(filled) };
            let count = entry.NumberOfThreads as usize;
            let threads_end = offset + threads_at + count * size_of::<SYSTEM_EXTENDED_THREAD_INFORMATION>();
            let extension_end = threads_end + size_of::<SYSTEM_PROCESS_INFORMATION_EXTENSION>();
            if extension_end > end {
                break;
            }

            let thread = |i: usize| unsafe {
                base.add(offset + threads_at + i * size_of::<SYSTEM_EXTENDED_THREAD_INFORMATION>())
                    .cast::<SYSTEM_EXTENDED_THREAD_INFORMATION>()
                    .read_unaligned()
                    .ThreadInfo
            };
            let suspended = count > 0
                && (0..count).all(|i| {
                    let t = thread(i);
                    t.ThreadState == THREAD_WAITING && t.WaitReason == WAIT_REASON_SUSPENDED
                });
            let extension = unsafe {
                base.add(threads_end)
                    .cast::<SYSTEM_PROCESS_INFORMATION_EXTENSION>()
                    .read_unaligned()
            };
            let disk = extension.DiskCounters;
            let quad = |v: ntapi::winapi::shared::ntdef::LARGE_INTEGER| unsafe { *v.QuadPart() } as u64;

            self.rows.push(Row {
                offset,
                end,
                pid: entry.UniqueProcessId as usize as u32,
                parent_pid: entry.InheritedFromUniqueProcessId as usize as u32,
                session_id: entry.SessionId,
                sequence_number: extension.ProcessSequenceNumber,
                create_time: quad(entry.CreateTime),
                base_priority: entry.BasePriority,
                handles: entry.HandleCount,
                threads: entry.NumberOfThreads,
                suspended,
                user_time: quad(entry.UserTime),
                kernel_time: quad(entry.KernelTime),
                cycles: entry.CycleTime,
                working_set: entry.WorkingSetSize as u64,
                peak_working_set: entry.PeakWorkingSetSize as u64,
                private_working_set: quad(entry.WorkingSetPrivateSize),
                commit: entry.PagefileUsage as u64,
                paged_pool: entry.QuotaPagedPoolUsage as u64,
                nonpaged_pool: entry.QuotaNonPagedPoolUsage as u64,
                page_faults: entry.PageFaultCount,
                io_read_ops: quad(entry.ReadOperationCount),
                io_write_ops: quad(entry.WriteOperationCount),
                io_other_ops: quad(entry.OtherOperationCount),
                io_read_bytes: quad(entry.ReadTransferCount),
                io_write_bytes: quad(entry.WriteTransferCount),
                io_other_bytes: quad(entry.OtherTransferCount),
                disk_read_ops: disk.ReadOperationCount,
                disk_write_ops: disk.WriteOperationCount,
                disk_flush_ops: disk.FlushOperationCount,
                disk_read_bytes: disk.BytesRead,
                disk_write_bytes: disk.BytesWritten,
                job_object_id: extension.JobObjectId,
            });

            if next == 0 {
                break;
            }
            offset += next;
        }
        self.rows.sort_unstable_by_key(|row| row.pid);
    }

    fn extension_at(row: &Row) -> usize {
        row.offset
            + offset_of!(SYSTEM_PROCESS_INFORMATION, Threads)
            + row.threads as usize * size_of::<SYSTEM_EXTENDED_THREAD_INFORMATION>()
    }

    fn extension(&self, row: &Row) -> SYSTEM_PROCESS_INFORMATION_EXTENSION {
        unsafe {
            self.bytes()
                .as_ptr()
                .add(Self::extension_at(row))
                .cast::<SYSTEM_PROCESS_INFORMATION_EXTENSION>()
                .read_unaligned()
        }
    }

    fn tail(&self, row: &Row, at: usize) -> Option<&[u8]> {
        if at == 0 {
            return None;
        }
        self.bytes().get(Self::extension_at(row) + at..row.end)
    }

    /// The file name the kernel gives the process; Idle has none.
    pub fn image_name(&self, row: &Row) -> String {
        let entry = unsafe {
            self.bytes()
                .as_ptr()
                .add(row.offset)
                .cast::<SYSTEM_PROCESS_INFORMATION>()
                .read_unaligned()
        };
        let name = if entry.ImageName.Buffer.is_null() || entry.ImageName.Length == 0 {
            String::new()
        } else {
            let units = unsafe {
                std::slice::from_raw_parts(entry.ImageName.Buffer, entry.ImageName.Length as usize / 2)
            };
            String::from_utf16_lossy(units)
        };
        match (name.is_empty(), row.pid) {
            (true, IDLE_PROCESS_PID) => "System Idle Process".to_string(),
            (true, _) => "System".to_string(),
            (false, _) => file_name(&name).to_string(),
        }
    }

    /// The token user's SID as the kernel recorded it.
    pub fn user_sid(&self, row: &Row) -> Option<Box<[u8]>> {
        let bytes = self.tail(row, self.extension(row).UserSidOffset as usize)?;
        let (&revision, &count) = (bytes.first()?, bytes.get(1)?);
        let len = 8 + 4 * count as usize;
        (revision == 1 && count <= 15).then(|| bytes.get(..len).map(Box::from))?
    }

    /// The package the process runs from; empty for an unpackaged one.
    pub fn package_full_name(&self, row: &Row) -> String {
        self.wide_at(row, self.extension(row).PackageFullNameOffset as usize)
    }

    /// The package-relative application id, the part after `!` in the AUMID.
    pub fn app_id(&self, row: &Row) -> String {
        self.wide_at(row, self.extension(row).AppIdOffset as usize)
    }

    fn wide_at(&self, row: &Row, at: usize) -> String {
        let Some(bytes) = self.tail(row, at) else {
            return String::new();
        };
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|&unit| unit != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// `\Device\HarddiskVolume3\Windows\explorer.exe` → `explorer.exe`.
pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_and_system_are_kernel_whatever_they_are_called() {
        assert!(is_kernel_pseudo_process(0, 0, "System Idle Process"));
        assert!(is_kernel_pseudo_process(4, 0, "System"));
    }

    #[test]
    fn imageless_processes_the_kernel_starts_are_kernel() {
        for name in ["Registry", "Memory Compression", "Secure System"] {
            assert!(is_kernel_pseudo_process(232, 4, name), "{name}");
        }
    }

    #[test]
    fn a_system32_binary_of_another_account_is_not_kernel() {
        for name in ["csrss.exe", "dwm.exe", "fontdrvhost.exe", "NgcIso.exe", "vmmemWSL"] {
            assert!(!is_kernel_pseudo_process(1072, 880, name), "{name}");
        }
    }

    #[test]
    fn borrowing_a_kernel_name_is_not_enough() {
        assert!(!is_kernel_pseudo_process(9000, 5120, "Registry"));
        assert!(!is_kernel_pseudo_process(9001, 5120, "Memory Compression"));
    }

    #[test]
    fn a_device_path_is_cut_to_the_file_name() {
        assert_eq!(file_name(r"\Device\HarddiskVolume3\Windows\explorer.exe"), "explorer.exe");
        assert_eq!(file_name("Registry"), "Registry");
    }

    #[test]
    #[ignore = "requires admin"]
    fn the_list_holds_this_process_with_its_own_sequence_number() {
        let mut processes = Processes::new();
        processes.read().expect("elevated");
        let rows = processes.rows();
        assert!(rows.len() > 10, "{} rows", rows.len());

        let me = rows.iter().find(|r| r.pid == std::process::id()).expect("this process");
        assert_ne!(me.sequence_number, 0);
        assert!(me.create_time > 0 && me.threads > 0 && me.working_set > 0);
        assert!(me.private_working_set <= me.working_set);
        assert!(!me.suspended);
        assert!(processes.image_name(me).ends_with(".exe"));
        let sid = processes.user_sid(me).expect("a user");
        assert_eq!(sid[..8], [1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(processes.package_full_name(me), "");

        let packaged = rows
            .iter()
            .find(|r| !processes.package_full_name(r).is_empty())
            .expect("a packaged process, such as a system app");
        let (package, app) = (processes.package_full_name(packaged), processes.app_id(packaged));
        assert_eq!(package.split('_').count(), 5, "{package}");
        assert!(!app.is_empty() && !app.contains('!'), "{app}");

        let idle = rows.iter().find(|r| r.pid == 0).expect("idle");
        assert_eq!(idle.sequence_number, 0);
        assert_eq!(processes.image_name(idle), "System Idle Process");
        let mut sequences: Vec<u64> = rows.iter().map(|r| r.sequence_number).collect();
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(sequences.len(), rows.len(), "sequence numbers are unique");
    }

    #[test]
    #[ignore = "requires admin"]
    fn a_second_read_reuses_the_buffer() {
        let mut processes = Processes::new();
        processes.read().expect("elevated");
        let first = processes.buf.as_ptr();
        processes.read().expect("elevated");
        assert_eq!(processes.buf.as_ptr(), first);
    }
}
