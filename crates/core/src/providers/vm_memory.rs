use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use anyhow::Result;
use windows_core::PWSTR;

use crate::bindings::{
    ERROR_BAD_LENGTH, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, GetLastError, GetMappedFileNameW,
    GetSystemInfo, HANDLE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ, QueryWorkingSet, SYSTEM_INFO, VirtualQueryEx,
};
use crate::providers::prober::{Listed, Prober, Seen};
use crate::providers::utils::query_sequence_number;
use crate::providers::vm_host::VmHosts;
use crate::sample::NO_DATA_U64;
use crate::snapshot::Row;
use crate::win::OwnedProcess;

struct Limits;

impl Limits {
    const PERIOD: Duration = Duration::from_secs(1);
    const FRESH: Duration = Duration::from_secs(10);
    const SCAN: Duration = Duration::from_secs(2);
    const REGIONS: usize = 65_536;
    const PAGES: usize = 16 << 20;
    const FILES: usize = 128;
}

#[derive(Clone, Copy)]
struct Reading {
    sequence: u64,
    at: Instant,
    bytes: u64,
}

pub struct VmMemory {
    prober: Prober<Reading>,
    submitted: Option<Instant>,
}

impl VmMemory {
    pub fn start() -> Result<Self> {
        Ok(Self {
            prober: Prober::start("vm-working-set", due, |pid| {
                probe(pid).unwrap_or(Reading {
                    sequence: 0,
                    at: Instant::now(),
                    bytes: NO_DATA_U64,
                })
            })?,
            submitted: None,
        })
    }

    pub fn read(&mut self, rows: &[Row], hosts: &VmHosts) {
        let now = Instant::now();
        if self.submitted.is_some_and(|at| now - at < Limits::PERIOD) {
            return;
        }
        self.submitted = Some(now);
        self.prober
            .read(rows.iter().filter(|row| hosts.get(row) == Some(true)));
    }

    pub fn get(&self, row: &Row, vm_host: bool) -> u64 {
        if !vm_host {
            return NO_DATA_U64;
        }
        self.prober
            .get(row)
            .map_or(NO_DATA_U64, |reading| reading.for_row(row))
    }
}

impl Reading {
    fn for_row(self, row: &Row) -> u64 {
        if self.sequence == row.sequence_number && self.at.elapsed() <= Limits::FRESH {
            self.bytes
        } else {
            NO_DATA_U64
        }
    }
}

fn due(last: Option<&Seen>, listed: &Listed, now: Instant) -> bool {
    last.is_none_or(|last| {
        last.sequence_number != listed.sequence_number || now - last.at >= Limits::PERIOD
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Backing {
    volume: u64,
    file: [u8; 16],
    bytes: u64,
}

struct BackingFile {
    file: File,
    identity: Backing,
}

#[derive(Clone, Debug)]
struct View {
    base: usize,
    end: usize,
    backing: Backing,
    complete: bool,
}

fn duplicates(views: &mut [View]) -> Vec<(usize, usize)> {
    views.sort_unstable_by_key(|view| view.base);
    let mut seen = HashSet::new();
    views
        .iter()
        .filter_map(|view| {
            if !view.complete || (view.end - view.base) as u64 != view.backing.bytes {
                return None;
            }
            (!seen.insert(view.backing)).then_some((view.base, view.end))
        })
        .collect()
}

fn count(
    blocks: &[usize],
    excluded: &[(usize, usize)],
    page: usize,
    started: Instant,
) -> Option<u64> {
    let mut kept = 0u64;
    for (index, &block) in blocks.iter().enumerate() {
        if index % 4096 == 0 && started.elapsed() > Limits::SCAN {
            return None;
        }
        let address = (block >> 12).checked_mul(page)?;
        let index = excluded.partition_point(|&(base, _)| base <= address);
        if index == 0 || address >= excluded[index - 1].1 {
            kept = kept.checked_add(page as u64)?;
        }
    }
    Some(kept)
}

fn probe(pid: u32) -> Option<Reading> {
    let started = Instant::now();
    let process = OwnedProcess::open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid).ok()?;
    let sequence = unsafe { query_sequence_number(process.0) }?;
    let mut system = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut system) };
    let mut files = HashMap::new();
    let mut views = mappings(
        process.0,
        system.lpMaximumApplicationAddress as usize,
        &mut files,
        started,
    )?;
    let excluded = duplicates(&mut views);
    let blocks = working_set(process.0, started)?;
    let bytes = count(&blocks, &excluded, system.dwPageSize as usize, started)?;
    for backing in files.values() {
        if identity(&backing.file)? != backing.identity {
            return None;
        }
    }
    Some(Reading {
        sequence,
        at: Instant::now(),
        bytes,
    })
}

fn working_set(process: HANDLE, started: Instant) -> Option<Vec<usize>> {
    let mut blocks = vec![0usize; 16_384];
    for _ in 0..4 {
        if started.elapsed() > Limits::SCAN {
            return None;
        }
        let size = u32::try_from(blocks.len().checked_mul(size_of::<usize>())?).ok()?;
        let ok = unsafe { QueryWorkingSet(process, blocks.as_mut_ptr().cast(), size) }.as_bool();
        let entries = blocks[0];
        if ok {
            if entries >= blocks.len() || entries > Limits::PAGES {
                return None;
            }
            blocks.truncate(entries + 1);
            blocks.remove(0);
            return Some(blocks);
        }
        if unsafe { GetLastError() } != ERROR_BAD_LENGTH as u32 || entries > Limits::PAGES {
            return None;
        }
        let size = entries.checked_add(entries / 8)?.checked_add(2)?;
        if size > Limits::PAGES + 1 {
            return None;
        }
        blocks.resize(size, 0);
    }
    None
}

fn mappings(
    process: HANDLE,
    maximum: usize,
    files: &mut HashMap<String, BackingFile>,
    started: Instant,
) -> Option<Vec<View>> {
    let mut address = 0usize;
    let mut allocations: BTreeMap<usize, Option<View>> = BTreeMap::new();
    for _ in 0..Limits::REGIONS {
        if address > maximum {
            return Some(allocations.into_values().flatten().collect());
        }
        if started.elapsed() > Limits::SCAN {
            return None;
        }
        let mut info = MEMORY_BASIC_INFORMATION::default();
        if unsafe {
            VirtualQueryEx(
                process,
                Some(address as *const _),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0
        {
            return None;
        }
        let base = info.BaseAddress as usize;
        let end = base.checked_add(info.RegionSize)?;
        if end <= address {
            return None;
        }
        if info.Type == MEM_MAPPED as u32 {
            let allocation = info.AllocationBase as usize;
            if let Some(view) = allocations.get_mut(&allocation) {
                if let Some(view) = view {
                    view.complete &= view.end == base && info.Protect & (8 | 128) == 0;
                    view.end = end;
                }
            } else {
                let mut path = [0u16; 2048];
                let length = unsafe {
                    GetMappedFileNameW(
                        process,
                        base as *const _,
                        PWSTR(path.as_mut_ptr()),
                        path.len() as u32,
                    )
                } as usize;
                if length >= path.len() - 1 {
                    return None;
                }
                let path = String::from_utf16(&path[..length]).ok()?;
                let view = if path.to_ascii_lowercase().ends_with(".vmem") {
                    if !path.starts_with(r"\Device\HarddiskVolume") {
                        return None;
                    }
                    if !files.contains_key(&path) {
                        if files.len() >= Limits::FILES {
                            return None;
                        }
                        let file = OpenOptions::new()
                            .access_mode(FILE_READ_ATTRIBUTES as u32)
                            .share_mode(
                                (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u32,
                            )
                            .open(format!(r"\\?\GLOBALROOT{path}"))
                            .ok()?;
                        let identity = identity(&file)?;
                        files.insert(path.clone(), BackingFile { file, identity });
                    }
                    Some(View {
                        base: allocation,
                        end,
                        backing: files.get(&path)?.identity,
                        complete: allocation == base && info.Protect & (8 | 128) == 0,
                    })
                } else {
                    None
                };
                allocations.insert(allocation, view);
            }
        }
        address = end;
    }
    None
}

fn identity(file: &File) -> Option<Backing> {
    let mut id = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .ok()
    .ok()?;
    Some(Backing {
        volume: id.VolumeSerialNumber,
        file: id.FileId.Identifier,
        bytes: file.metadata().ok()?.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::{
        CloseHandle, CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE,
        UnmapViewOfFile,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn backing(file: u8, bytes: u64) -> Backing {
        Backing {
            volume: 1,
            file: [file; 16],
            bytes,
        }
    }

    fn view(base: usize, bytes: usize, backing: Backing) -> View {
        View {
            base,
            end: base + bytes,
            backing,
            complete: true,
        }
    }

    #[test]
    fn first_complete_view_in_address_order_is_retained() {
        let file = backing(1, 8192);
        let mut views = [
            view(0x50000, 8192, file),
            view(0x10000, 8192, file),
            view(0x30000, 8192, file),
        ];
        let excluded = duplicates(&mut views);
        assert_eq!(excluded, [(0x30000, 0x32000), (0x50000, 0x52000)]);
        let blocks = [0x10000 | 256, 0x31000 | 256, 0x50000 | 256, 0x90000];
        assert_eq!(count(&blocks, &excluded, 4096, Instant::now()), Some(8192));
    }

    #[test]
    fn different_files_volumes_lengths_and_partial_views_are_not_collapsed() {
        let first = backing(1, 8192);
        let mut second_volume = first;
        second_volume.volume = 2;
        let mut partial = view(0x70000, 8192, first);
        partial.complete = false;
        let mut views = [
            view(0x10000, 8192, first),
            view(0x20000, 8192, backing(2, 8192)),
            view(0x30000, 8192, second_volume),
            view(0x40000, 4096, first),
            view(0x50000, 16384, backing(1, 16384)),
            partial,
        ];
        assert!(duplicates(&mut views).is_empty());
    }

    #[test]
    fn inaccessible_and_gone_processes_have_no_reading() {
        assert!(probe(0).is_none());
        assert!(probe(u32::MAX).is_none());
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "exit", "0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(probe(pid).is_none());
    }

    #[test]
    #[ignore = "requires an explicitly selected live VM-host PID and elevated read access"]
    fn live_vm_host_probe() {
        let pid = std::env::var("UNIPROC_VM_PROBE_PID")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let reading = probe(pid).expect("the live VM-host probe must complete within its limits");
        let process = OwnedProcess::open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid).unwrap();
        let raw = working_set(process.0, Instant::now()).unwrap().len() as u64 * 4096;
        assert_ne!(reading.bytes, NO_DATA_U64);
        println!(
            "pid={pid} sequence={} raw_working_set={raw} vm_working_set={} heuristic=first-full-file-view",
            reading.sequence, reading.bytes
        );
    }

    #[test]
    fn process_instance_freshness_and_vm_host_are_required() {
        let row = Row {
            pid: 42,
            sequence_number: 123,
            ..Default::default()
        };
        let reading = Reading {
            sequence: 123,
            at: Instant::now(),
            bytes: 0,
        };
        assert_eq!(reading.for_row(&row), 0);
        assert_eq!(
            Reading {
                sequence: 124,
                ..reading
            }
            .for_row(&row),
            NO_DATA_U64
        );
        assert_eq!(
            Reading {
                at: Instant::now() - Limits::FRESH - Limits::PERIOD,
                ..reading
            }
            .for_row(&row),
            NO_DATA_U64
        );
        let reader = VmMemory::start().unwrap();
        assert_eq!(reader.get(&row, false), NO_DATA_U64);
        assert_eq!(reader.get(&row, true), NO_DATA_U64);
        assert!(count(&[], &[], 4096, Instant::now()).is_some());
        assert!(
            count(
                &[0],
                &[],
                4096,
                Instant::now() - Limits::SCAN - Limits::PERIOD
            )
            .is_none()
        );
    }

    #[test]
    fn probes_are_not_due_faster_than_once_a_second() {
        let now = Instant::now();
        let listed = Listed {
            pid: 42,
            sequence_number: 7,
            shared: 0,
        };
        let seen = Seen {
            sequence_number: 7,
            at: now,
            shared: 0,
        };
        assert!(due(None, &listed, now));
        assert!(!due(Some(&seen), &listed, now + Limits::PERIOD / 2));
        assert!(due(Some(&seen), &listed, now + Limits::PERIOD));
        assert!(due(
            Some(&seen),
            &Listed {
                sequence_number: 8,
                ..listed
            },
            now
        ));
    }

    struct MappingFixture {
        file: File,
        path: std::path::PathBuf,
        mapping: HANDLE,
        views: Vec<*mut std::ffi::c_void>,
    }

    impl MappingFixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "uniproc-alias-{}-{}.vmem",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.set_len(16 << 20).unwrap();
            let mapping = unsafe {
                CreateFileMappingW(
                    HANDLE(file.as_raw_handle()),
                    None,
                    PAGE_READWRITE as u32,
                    0,
                    16 << 20,
                    None,
                )
            };
            assert!(!mapping.0.is_null());
            Self {
                file,
                path,
                mapping,
                views: Vec::new(),
            }
        }

        fn map(&mut self, offset: u32, size: usize) -> usize {
            let address =
                unsafe { MapViewOfFile(self.mapping, FILE_MAP_WRITE as u32, 0, offset, size) };
            assert!(!address.is_null());
            self.views.push(address);
            for index in (0..size).step_by(4096) {
                unsafe { std::ptr::write_volatile(address.cast::<u8>().add(index), 1) };
            }
            address as usize
        }
    }

    impl Drop for MappingFixture {
        fn drop(&mut self) {
            for &view in &self.views {
                unsafe {
                    let _ = UnmapViewOfFile(view);
                }
            }
            unsafe {
                let _ = CloseHandle(self.mapping);
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn real_file_views_deduplicate_full_views_but_keep_a_different_offset_partial_view() {
        let mut fixture = MappingFixture::new();
        let first = fixture.map(0, 16 << 20);
        let second = fixture.map(0, 16 << 20);
        let partial = fixture.map(8 << 20, 8 << 20);
        let key = identity(&fixture.file).unwrap();
        let started = Instant::now();
        let process = OwnedProcess::open(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            std::process::id(),
        )
        .unwrap();
        let mut system = SYSTEM_INFO::default();
        unsafe { GetSystemInfo(&mut system) };
        let mut files = HashMap::new();
        let mut views = mappings(
            process.0,
            system.lpMaximumApplicationAddress as usize,
            &mut files,
            started,
        )
        .unwrap();
        views.retain(|view| view.backing == key);
        assert_eq!(views.len(), 3);
        let excluded = duplicates(&mut views);
        let later = first.max(second);
        assert_eq!(excluded, [(later, later + (16 << 20))]);
        assert!(
            excluded
                .iter()
                .all(|&(base, end)| partial < base || partial >= end)
        );
        let blocks = working_set(process.0, started).unwrap();
        let raw = blocks.len() as u64 * u64::from(system.dwPageSize);
        let corrected = count(&blocks, &excluded, system.dwPageSize as usize, started).unwrap();
        assert_eq!(raw - corrected, 16 << 20);
    }
}
