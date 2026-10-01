//! The part of each process's working set it holds alone in pages backed by
//! a section: mapped files, images and pagefile-backed shared memory.

use std::sync::OnceLock;
use std::time::Instant;

use anyhow::Result;
use windows::Win32::{
    ERROR_BAD_LENGTH, GetLastError, GetSystemInfo, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, QueryWorkingSet,
    SYSTEM_INFO,
};

use crate::providers::prober::{FULL_ROUND, IsDue, Listed, Prober, Seen};
use crate::sample::NO_DATA_U64;
use crate::snapshot::Row;
use crate::win::OwnedProcess;

const SHARE_COUNT_SHIFT: usize = 5;
const SHARE_COUNT_MASK: usize = 0b111;
const SHARED: usize = 1 << 8;
const FIRST_BLOCKS: usize = 1 << 16;

/// How far the shared working set moves before the process is probed again:
/// this many bytes, or one part in [`MOVED_PARTS`].
const MOVED_BYTES: u64 = 4 << 20;
const MOVED_PARTS: u64 = 20;

/// Each listed process's section-backed working set held alone, probed on a
/// thread of its own: as it shows up, when its shared working set moves by
/// [`MOVED_BYTES`] or a [`MOVED_PARTS`]th, and at least every
/// [`FULL_ROUND`]. A walk of a working set costs about 270 ns a page, and a
/// shared working set at rest leaves the answer as it was.
pub struct Mapped(Prober<u64>);

impl Mapped {
    pub fn start() -> Result<Self> {
        let mut blocks = Vec::new();
        let prober = Prober::start("exclusive-mapped", IS_DUE, move |pid| exclusive_mapped(pid, &mut blocks))?;
        Ok(Self(prober))
    }

    /// Hands the worker the processes of `rows` and their shared working sets.
    pub fn read(&self, rows: &[Row]) {
        self.0.read(rows);
    }

    /// The bytes last probed for this process; [`NO_DATA_U64`] when its
    /// working set could not be read or was not probed yet.
    pub fn get(&self, row: &Row) -> u64 {
        self.0.get(row).unwrap_or(NO_DATA_U64)
    }
}

const IS_DUE: IsDue = is_due;

/// Whether `listed` is to be probed now, given what was seen of it last.
fn is_due(last: Option<&Seen>, listed: &Listed, now: Instant) -> bool {
    let Some(last) = last.filter(|last| last.sequence_number == listed.sequence_number) else {
        return true;
    };
    let moved = last.shared.abs_diff(listed.shared);
    moved >= MOVED_BYTES || moved * MOVED_PARTS >= last.shared.max(1) || now - last.at >= FULL_ROUND
}

fn page_size() -> u64 {
    static PAGE: OnceLock<u64> = OnceLock::new();
    *PAGE.get_or_init(|| {
        let mut info = SYSTEM_INFO::default();
        unsafe { GetSystemInfo(&mut info) };
        info.dwPageSize as u64
    })
}

/// Whether Windows tells this process how many processes share a page. To a
/// caller that is not elevated it reports every shared page as shared by the
/// most it can count, so nothing would ever look held alone; this process's
/// own image has pages only it holds, which an honest answer shows.
fn share_counts_visible() -> bool {
    static VISIBLE: OnceLock<bool> = OnceLock::new();
    *VISIBLE.get_or_init(|| {
        let mut blocks = Vec::new();
        working_set(std::process::id(), &mut blocks)
            .is_some_and(|blocks| blocks.iter().any(|&block| block & SHARED != 0 && share_count(block) < SHARE_COUNT_MASK))
    })
}

fn share_count(block: usize) -> usize {
    (block >> SHARE_COUNT_SHIFT) & SHARE_COUNT_MASK
}

/// Bytes of the working set of `pid` in shared pages that no other process
/// has in its working set; [`NO_DATA_U64`] when it cannot be read.
fn exclusive_mapped(pid: u32, blocks: &mut Vec<usize>) -> u64 {
    if !share_counts_visible() {
        return NO_DATA_U64;
    }
    working_set(pid, blocks).map_or(NO_DATA_U64, |blocks| {
        let alone = blocks.iter().filter(|&&block| block & SHARED != 0 && share_count(block) == 1).count();
        alone as u64 * page_size()
    })
}

/// The working set blocks of `pid`, read into `blocks`, which grows as needed.
fn working_set(pid: u32, blocks: &mut Vec<usize>) -> Option<&[usize]> {
    let process = OwnedProcess::open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid).ok()?;
    if blocks.is_empty() {
        blocks.resize(FIRST_BLOCKS, 0);
    }
    for _ in 0..4 {
        let size = (blocks.len() * size_of::<usize>()) as u32;
        let read = unsafe { QueryWorkingSet(process.0, blocks.as_mut_ptr().cast(), size) }.as_bool();
        let entries = blocks[0];
        if read {
            return Some(&blocks[1..=entries.min(blocks.len() - 1)]);
        }
        if unsafe { GetLastError() } != ERROR_BAD_LENGTH as u32 {
            return None;
        }
        blocks.resize(entries + entries / 8 + 2, 0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hash::FxHashMap;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use windows::Win32::{
        CreateFileMappingW, FILE_MAP_WRITE, HANDLE, INVALID_HANDLE_VALUE, MapViewOfFile, PAGE_READWRITE,
        UnmapViewOfFile,
    };

    fn me() -> Row {
        Row {
            pid: std::process::id(),
            sequence_number: 1,
            ..Default::default()
        }
    }

    const SIZE: usize = 16 << 20;

    /// This process's exclusive bytes before and after mapping a view of
    /// `SIZE` bytes over `file`, or over the page file without one, and
    /// writing every page of it.
    fn before_and_after_a_view(file: HANDLE) -> (u64, u64) {
        let mut blocks = Vec::new();
        let before = exclusive_mapped(std::process::id(), &mut blocks);
        let mapping =
            unsafe { CreateFileMappingW(file, None, PAGE_READWRITE as u32, 0, SIZE as u32, None) };
        assert!(!mapping.0.is_null(), "a mapping");
        let view = unsafe { MapViewOfFile(mapping, FILE_MAP_WRITE as u32, 0, 0, SIZE) };
        assert!(!view.is_null(), "a view of the mapping");
        let bytes = unsafe { std::slice::from_raw_parts_mut(view as *mut u8, SIZE) };
        for page in bytes.chunks_mut(page_size() as usize) {
            page[0] = 7;
        }
        let after = exclusive_mapped(std::process::id(), &mut blocks);
        unsafe {
            let _ = UnmapViewOfFile(view);
            let _ = windows::Win32::CloseHandle(mapping);
        }
        (before, after)
    }

    fn holds_it_alone((before, after): (u64, u64)) {
        if !share_counts_visible() {
            assert_eq!((before, after), (NO_DATA_U64, NO_DATA_U64), "hidden share counts read as no data");
            return;
        }
        assert!(after >= before + SIZE as u64 * 9 / 10, "{before} then {after} with {SIZE} mapped");
    }

    #[test]
    fn shared_memory_written_here_alone_counts() {
        holds_it_alone(before_and_after_a_view(INVALID_HANDLE_VALUE));
    }

    #[test]
    fn a_file_mapped_and_written_here_alone_counts() {
        let path = std::env::temp_dir().join(format!("uniproc-mapped-{}.bin", std::process::id()));
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        let counted = before_and_after_a_view(HANDLE(file.as_raw_handle()));
        drop(file);
        let _ = std::fs::remove_file(&path);
        holds_it_alone(counted);
    }

    #[test]
    fn a_process_that_cannot_be_read_has_no_data() {
        assert_eq!(exclusive_mapped(0, &mut Vec::new()), NO_DATA_U64, "Idle");
    }

    fn until(mapped: &Mapped, row: &Row, done: impl Fn(u64) -> bool) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let bytes = mapped.get(row);
            if done(bytes) || Instant::now() > deadline {
                return bytes;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_process_is_probed_as_it_shows_up_and_forgotten_when_gone() {
        if !share_counts_visible() {
            return;
        }
        let mapped = Mapped::start().unwrap();
        mapped.read(&[me()]);
        assert_ne!(until(&mapped, &me(), |bytes| bytes != NO_DATA_U64), NO_DATA_U64);
        let other = Row { sequence_number: 2, ..me() };
        assert_eq!(mapped.get(&other), NO_DATA_U64, "another process under the same pid");
        mapped.read(&[]);
        assert_eq!(until(&mapped, &me(), |bytes| bytes == NO_DATA_U64), NO_DATA_U64);
    }

    #[test]
    fn a_process_is_due_when_new_moved_or_a_round_old() {
        let probed = Instant::now();
        let soon = probed + Duration::from_secs(1);
        let listed = |shared| Listed { pid: 8, sequence_number: 1, shared };
        let seen = |shared| Seen { sequence_number: 1, shared, at: probed };
        assert!(is_due(None, &listed(100 << 20), soon), "new");
        assert!(is_due(Some(&Seen { sequence_number: 2, ..seen(100 << 20) }), &listed(100 << 20), soon), "pid reused");
        assert!(!is_due(Some(&seen(100 << 20)), &listed((100 << 20) + (3 << 20)), soon), "3 MB of 100");
        assert!(is_due(Some(&seen(100 << 20)), &listed((100 << 20) - (4 << 20)), soon), "4 MB of 100");
        assert!(is_due(Some(&seen(20 << 20)), &listed((20 << 20) + (1 << 20)), soon), "a twentieth");
        assert!(!is_due(Some(&seen(0)), &listed(0), soon), "nothing shared, nothing moved");
        assert!(is_due(Some(&seen(100 << 20)), &listed(100 << 20), probed + FULL_ROUND), "a round old");
    }

    #[test]
    #[ignore = "requires admin; a measurement, run in release with --nocapture"]
    fn what_probing_only_a_moved_shared_set_costs() {
        crate::privileges::enable(windows::core::w!("SeDebugPrivilege")).unwrap();
        let mut processes = crate::snapshot::Processes::new();
        let mut blocks = Vec::new();
        let mut last: FxHashMap<(u32, u64), u64> = FxHashMap::default();
        let (mut probes, mut pages, mut spent, mut slowest) = (0usize, 0usize, Duration::ZERO, Duration::ZERO);
        let seconds = 60;
        for second in 0..seconds {
            processes.read().unwrap();
            for row in processes.rows() {
                let shared = row.working_set.saturating_sub(row.private_working_set);
                let moved = match last.get(&(row.pid, row.sequence_number)) {
                    Some(&before) => {
                        let delta = shared.abs_diff(before);
                        delta >= 4 << 20 || delta * 20 >= before.max(1)
                    }
                    None => second == 0,
                };
                if moved {
                    let at = Instant::now();
                    let read = exclusive_mapped(row.pid, &mut blocks) != NO_DATA_U64;
                    let took = at.elapsed();
                    spent += took;
                    slowest = slowest.max(took);
                    probes += 1;
                    if read {
                        pages += blocks[0];
                    }
                    last.insert((row.pid, row.sequence_number), shared);
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        let first_round = processes.rows().len();
        eprintln!(
            "{seconds} s: {probes} probes ({first_round} processes, the first second probes them all), {pages} pages, {:.1} ms in all, {:.2}% of a core, slowest {:.1} ms",
            spent.as_secs_f64() * 1000.0,
            spent.as_secs_f64() / seconds as f64 * 100.0,
            slowest.as_secs_f64() * 1000.0,
        );
    }

    #[test]
    #[ignore = "requires admin; a measurement, run in release with --nocapture"]
    fn what_a_round_over_every_process_costs() {
        crate::privileges::enable(windows::core::w!("SeDebugPrivilege")).unwrap();
        let mut processes = crate::snapshot::Processes::new();
        processes.read().unwrap();
        let rows = processes.rows();
        assert!(share_counts_visible(), "elevated, the share counts are told");
        let mut blocks = Vec::new();
        let _ = exclusive_mapped(std::process::id(), &mut blocks);
        for round in 0..3 {
            let started = Instant::now();
            let mut each = Vec::new();
            for row in rows {
                let at = Instant::now();
                let value = exclusive_mapped(row.pid, &mut blocks);
                let took = at.elapsed();
                if value != NO_DATA_U64 {
                    each.push((processes.image_name(row).to_string(), blocks[0], took, value));
                }
            }
            let took = started.elapsed();
            let pages: usize = each.iter().map(|(_, pages, _, _)| pages).sum();
            eprintln!(
                "round {round}: {} processes, {} read, {:.1} ms, {pages} working set pages ({:.1} ns a page), buffer {} KB",
                rows.len(),
                each.len(),
                took.as_secs_f64() * 1000.0,
                took.as_secs_f64() * 1e9 / pages.max(1) as f64,
                blocks.len() * size_of::<usize>() / 1024,
            );
            if round == 2 {
                each.sort_by_key(|(_, _, took, _)| std::cmp::Reverse(*took));
                for (name, pages, took, value) in each.iter().take(10) {
                    eprintln!(
                        "  {name:<28} {:>7} MB in the working set, {:>6} MB alone in sections, {:>7.2} ms",
                        (pages * page_size() as usize) >> 20,
                        value >> 20,
                        took.as_secs_f64() * 1000.0,
                    );
                }
            }
        }
    }
}
