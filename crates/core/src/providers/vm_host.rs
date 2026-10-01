//! Whether a process runs a virtual machine on the Windows Hypervisor
//! Platform: it has loaded WinHvPlatform.dll and holds a VID partition,
//! `\Device\VidExo`, open.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use windows::Win32::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, EnumProcessModulesEx, GetCurrentProcess, GetMappedFileNameW,
    HANDLE, HMODULE, LIST_MODULES_ALL, NtQueryInformationProcess, NtQueryObject, OBJECT_INFORMATION_CLASS,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESSINFOCLASS,
};
use windows::core::PWSTR;

use crate::providers::prober::{self, FULL_ROUND, IsDue, Listed, Prober, Seen};
use crate::providers::utils::{bytes_of, unicode_string_in};
use crate::snapshot::Row;
use crate::win::OwnedProcess;

/// A process with less of its working set in shared pages is not checked:
/// a guest's RAM is mapped, and no guest runs in less.
pub const CANDIDATE: u64 = 256 << 20;
/// How far a checked process's shared working set grows before it is
/// checked again: a guest started later fills its RAM.
const GROWN: u64 = 256 << 20;
/// How long a handle's name may take; a synchronous file with I/O pending
/// holds its name back until the I/O completes.
const NAMED_WITHIN: Duration = Duration::from_millis(500);

const PLATFORM: &str = "winhvplatform.dll";
const PARTITION: &str = r"\Device\VidExo";

const PROCESS_HANDLE_INFORMATION: PROCESSINFOCLASS = 51;
const OBJECT_NAME_INFORMATION: OBJECT_INFORMATION_CLASS = 1;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const HANDLES_HEADER: usize = 2 * size_of::<usize>();
const FIRST_HANDLE_WORDS: usize = 4096;
const FIRST_MODULES: usize = 256;
const NAME_WORDS: usize = 128;

/// Which listed processes host a virtual machine, checked on a thread of
/// its own: as one passes [`CANDIDATE`], when its shared working set grows
/// by [`GROWN`], and at least every [`FULL_ROUND`].
pub struct VmHosts(Prober<Option<bool>>);

impl VmHosts {
    pub fn start() -> Result<Self> {
        let mut scratch = Scratch::default();
        let prober = Prober::start("vm-hosts", IS_DUE, move |pid| vm_host(pid, &mut scratch))?;
        Ok(Self(prober))
    }

    /// Hands the worker the candidates among `rows`.
    pub fn read(&self, rows: &[Row]) {
        self.0.read(rows.iter().filter(|row| candidate(row)));
    }

    /// Off below [`CANDIDATE`]; `None` before the first check and when the
    /// process's modules or handles cannot be read.
    pub fn get(&self, row: &Row) -> Option<bool> {
        if !candidate(row) {
            return Some(false);
        }
        self.0.get(row).flatten()
    }
}

fn candidate(row: &Row) -> bool {
    prober::shared(row) >= CANDIDATE
}

const IS_DUE: IsDue = is_due;

fn is_due(last: Option<&Seen>, listed: &Listed, now: Instant) -> bool {
    let Some(last) = last.filter(|last| last.sequence_number == listed.sequence_number) else {
        return true;
    };
    listed.shared >= last.shared.saturating_add(GROWN) || now.saturating_duration_since(last.at) >= FULL_ROUND
}

#[derive(Default)]
struct Scratch {
    modules: Vec<usize>,
    handles: Vec<u64>,
    namer: Option<Namer>,
}

fn vm_host(pid: u32, scratch: &mut Scratch) -> Option<bool> {
    let process = OwnedProcess::open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, pid).ok()?;
    if !loads(process.0, PLATFORM, &mut scratch.modules)? {
        return Some(false);
    }
    holds_partition(process.0, &mut scratch.handles, &mut scratch.namer)
}

/// Whether `process` has a module whose file is called `name`.
fn loads(process: HANDLE, name: &str, modules: &mut Vec<usize>) -> Option<bool> {
    if modules.is_empty() {
        modules.resize(FIRST_MODULES, 0);
    }
    for _ in 0..4 {
        let mut needed = 0u32;
        let room = (modules.len() * size_of::<HMODULE>()) as u32;
        let listed = unsafe {
            EnumProcessModulesEx(process, modules.as_mut_ptr().cast(), room, &mut needed, LIST_MODULES_ALL as u32)
        };
        if !listed.as_bool() {
            return None;
        }
        let count = needed as usize / size_of::<HMODULE>();
        if count <= modules.len() {
            let mut path = [0u16; 512];
            return Some(modules[..count].iter().any(|&module| {
                let len = unsafe {
                    GetMappedFileNameW(process, module as *const c_void, PWSTR(path.as_mut_ptr()), path.len() as u32)
                };
                file_name_is(&path[..len as usize], name)
            }));
        }
        modules.resize(count + count / 8, 0);
    }
    None
}

fn file_name_is(path: &[u16], name: &str) -> bool {
    let file = path.rsplit(|&unit| unit == u16::from(b'\\')).next().unwrap_or(path);
    String::from_utf16_lossy(file).eq_ignore_ascii_case(name)
}

/// One entry of ProcessHandleInformation.
#[repr(C)]
#[derive(Clone, Copy)]
struct HandleEntry {
    handle: usize,
    _handle_count: usize,
    _pointer_count: usize,
    _granted_access: u32,
    object_type_index: u32,
    _attributes: u32,
    _reserved: u32,
}

/// The handles `process` holds, read into `scratch`, which grows as needed.
fn handles(process: HANDLE, scratch: &mut Vec<u64>) -> Option<&[HandleEntry]> {
    if scratch.is_empty() {
        scratch.resize(FIRST_HANDLE_WORDS, 0);
    }
    for _ in 0..4 {
        let mut needed = 0u32;
        let status = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_HANDLE_INFORMATION,
                scratch.as_mut_ptr().cast(),
                (scratch.len() * 8) as u32,
                Some(&mut needed),
            )
        };
        if status.0 == STATUS_INFO_LENGTH_MISMATCH {
            let grown = (needed as usize).div_ceil(8).max(scratch.len() * 2);
            scratch.resize(grown, 0);
            continue;
        }
        if status.is_err() {
            return None;
        }
        let room = (scratch.len() * 8 - HANDLES_HEADER) / size_of::<HandleEntry>();
        let count = (scratch[0] as usize).min(room);
        let entries = unsafe { scratch.as_ptr().cast::<u8>().add(HANDLES_HEADER).cast::<HandleEntry>() };
        return Some(unsafe { std::slice::from_raw_parts(entries, count) });
    }
    None
}

/// The object type index of files, as this process's own file handle shows it.
fn file_type() -> Option<u32> {
    static FILE: OnceLock<Option<u32>> = OnceLock::new();
    *FILE.get_or_init(|| {
        let file = std::fs::File::open(std::env::current_exe().ok()?).ok()?;
        let mine = file.as_raw_handle() as usize;
        let mut scratch = Vec::new();
        let entries = handles(unsafe { GetCurrentProcess() }, &mut scratch)?;
        entries.iter().find(|entry| entry.handle == mine).map(|entry| entry.object_type_index)
    })
}

/// Whether one of the files `process` holds open is the partition device;
/// `None` when its handles cannot be read or a name does not come in time.
fn holds_partition(process: HANDLE, scratch: &mut Vec<u64>, namer: &mut Option<Namer>) -> Option<bool> {
    let file = file_type()?;
    for entry in handles(process, scratch)?.iter().filter(|entry| entry.object_type_index == file) {
        let mut mine = HANDLE::default();
        let duplicated = unsafe {
            DuplicateHandle(
                process,
                HANDLE(entry.handle as *mut c_void),
                GetCurrentProcess(),
                &mut mine,
                0,
                false,
                DUPLICATE_SAME_ACCESS as u32,
            )
        };
        if !duplicated.as_bool() {
            continue;
        }
        if namer.is_none() {
            *namer = Namer::start();
        }
        let Some(asked) = namer.as_ref() else {
            let _ = unsafe { CloseHandle(mine) };
            return None;
        };
        match asked.names_partition(mine) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => {
                *namer = None;
                return None;
            }
        }
    }
    Some(false)
}

/// A thread that tells whether a handle duplicated into this process is the
/// partition device and closes it. A name query can hang; the thread is then
/// left to finish on its own and the next question starts another.
struct Namer {
    asks: Sender<usize>,
    answers: Receiver<bool>,
}

impl Namer {
    fn start() -> Option<Self> {
        let (asks, asked) = crossbeam_channel::unbounded::<usize>();
        let (answer, answers) = crossbeam_channel::unbounded();
        std::thread::Builder::new()
            .name("vm-host-names".into())
            .spawn(move || {
                let mut scratch = vec![0u64; NAME_WORDS];
                for handle in asked {
                    let handle = HANDLE(handle as *mut c_void);
                    let partition = names(handle, PARTITION, &mut scratch);
                    let _ = unsafe { CloseHandle(handle) };
                    if answer.send(partition).is_err() {
                        return;
                    }
                }
            })
            .ok()?;
        Some(Self { asks, answers })
    }

    /// `None` when the thread does not answer within [`NAMED_WITHIN`].
    fn names_partition(&self, handle: HANDLE) -> Option<bool> {
        if self.asks.send(handle.0 as usize).is_err() {
            let _ = unsafe { CloseHandle(handle) };
            return None;
        }
        self.answers.recv_timeout(NAMED_WITHIN).ok()
    }
}

fn names(handle: HANDLE, expected: &str, scratch: &mut [u64]) -> bool {
    let status = unsafe {
        NtQueryObject(
            Some(handle),
            OBJECT_NAME_INFORMATION,
            Some(scratch.as_mut_ptr().cast()),
            (scratch.len() * 8) as u32,
            None,
        )
    };
    status.is_ok()
        && unicode_string_in(bytes_of(scratch))
            .is_some_and(|name| String::from_utf16_lossy(&name).eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::{FreeLibrary, GetProcAddress, LoadLibraryW};
    use windows::core::{s, w};

    type CreatePartition = unsafe extern "system" fn(*mut isize) -> i32;
    type SetPartitionProperty = unsafe extern "system" fn(isize, i32, *const c_void, u32) -> i32;
    type SetupPartition = unsafe extern "system" fn(isize) -> i32;
    type DeletePartition = unsafe extern "system" fn(isize) -> i32;
    const PROCESSOR_COUNT: i32 = 0x1fff;

    #[test]
    fn this_process_hosts_a_machine_once_it_holds_a_partition() {
        let me = std::process::id();
        let mut scratch = Scratch::default();
        assert_eq!(vm_host(me, &mut scratch), Some(false), "before the platform is loaded");

        let platform = unsafe { LoadLibraryW(w!("WinHvPlatform.dll")) };
        if platform.0.is_null() {
            eprintln!("the Windows Hypervisor Platform is not installed here");
            return;
        }
        let process = OwnedProcess::open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, me).unwrap();
        assert_eq!(loads(process.0, PLATFORM, &mut Vec::new()), Some(true));
        assert_eq!(vm_host(me, &mut scratch), Some(false), "the platform loaded, no partition");

        type Exported = unsafe extern "system" fn() -> isize;
        let export = |name| unsafe { GetProcAddress(platform, name) }.expect("an export of the platform");
        let (create, set, setup, delete) = unsafe {
            (
                std::mem::transmute::<Exported, CreatePartition>(export(s!("WHvCreatePartition"))),
                std::mem::transmute::<Exported, SetPartitionProperty>(export(s!("WHvSetPartitionProperty"))),
                std::mem::transmute::<Exported, SetupPartition>(export(s!("WHvSetupPartition"))),
                std::mem::transmute::<Exported, DeletePartition>(export(s!("WHvDeletePartition"))),
            )
        };
        let mut partition = 0isize;
        let created = unsafe { create(&mut partition) };
        if created < 0 {
            eprintln!("no partition here: {created:#x}");
            unsafe { let _ = FreeLibrary(platform); }
            return;
        }
        let processors = 1u32;
        let set = unsafe { set(partition, PROCESSOR_COUNT, (&processors as *const u32).cast(), 4) };
        let set_up = unsafe { setup(partition) };
        let hosting = vm_host(me, &mut scratch);
        unsafe {
            delete(partition);
            let _ = FreeLibrary(platform);
        }
        assert!(set >= 0 && set_up >= 0, "set {set:#x}, setup {set_up:#x}");
        assert_eq!(hosting, Some(true), "a partition set up");
    }

    #[test]
    fn a_process_that_cannot_be_read_is_unknown() {
        assert_eq!(vm_host(0, &mut Scratch::default()), None, "Idle");
    }

    #[test]
    fn this_process_holds_files() {
        assert!(file_type().is_some());
    }

    #[test]
    fn a_candidate_is_due_when_new_grown_or_a_round_old() {
        let checked = Instant::now();
        let soon = checked + Duration::from_secs(1);
        let listed = |shared| Listed { pid: 8, sequence_number: 1, shared };
        let seen = |shared| Seen { sequence_number: 1, shared, at: checked };
        let gb = 1u64 << 30;
        assert!(is_due(None, &listed(gb), soon), "new");
        assert!(is_due(Some(&Seen { sequence_number: 2, ..seen(gb) }), &listed(gb), soon), "pid reused");
        assert!(!is_due(Some(&seen(gb)), &listed(gb + (255 << 20)), soon), "grown by 255 MB");
        assert!(is_due(Some(&seen(gb)), &listed(gb + GROWN), soon), "grown by 256 MB");
        assert!(!is_due(Some(&seen(gb)), &listed(gb / 2), soon), "shrunk");
        assert!(is_due(Some(&seen(gb)), &listed(gb), checked + FULL_ROUND), "a round old");
    }

    #[test]
    #[ignore = "requires admin; a measurement, run in release with --nocapture"]
    fn what_checking_the_candidates_costs() {
        crate::privileges::enable(windows::core::w!("SeDebugPrivilege")).unwrap();
        let mut processes = crate::snapshot::Processes::new();
        processes.read().unwrap();
        let mut scratch = Scratch::default();
        for row in processes.rows().iter().filter(|row| candidate(row)) {
            let at = Instant::now();
            let hosting = vm_host(row.pid, &mut scratch);
            eprintln!(
                "{:<28} {:>6} MB shared: {hosting:?} in {:.2} ms",
                processes.image_name(row).to_string(),
                prober::shared(row) >> 20,
                at.elapsed().as_secs_f64() * 1000.0,
            );
        }
    }
}
