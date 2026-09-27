//! What SystemFullProcessInformation (class 148) returns on this machine, and
//! what it costs:
//!   cargo run --release -p uniproc-windows-core --example process_probe
//!
//! Run elevated. Prints the call's cost and buffer size, rows whose sequence
//! number is 0, whether the extension's sequence number matches
//! ProcessSequenceNumber from a handle, suspended processes, and every process
//! whose EcoQoS state or priority class would put it in efficiency mode.

use std::mem::{offset_of, size_of, zeroed};
use std::ptr::null_mut;
use std::time::Instant;

use ntapi::ntexapi::{
    NtQuerySystemInformation, SYSTEM_EXTENDED_THREAD_INFORMATION, SYSTEM_PROCESS_INFORMATION,
    SYSTEM_PROCESS_INFORMATION_EXTENSION, SystemFullProcessInformation,
};
use ntapi::ntobapi::NtClose;
use ntapi::ntpsapi::{NtOpenProcess, NtQueryInformationProcess, PROCESS_PRIORITY_CLASS};
use ntapi::winapi::shared::ntdef::{HANDLE, OBJECT_ATTRIBUTES};
use ntapi::ntapi_base::CLIENT_ID;

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_PRIORITY_CLASS_INFO: u32 = 18;
const PROCESS_SEQUENCE_NUMBER: u32 = 92;
const PROCESS_POWER_THROTTLING_STATE: u32 = 77;
const EXECUTION_SPEED: u32 = 1;
const WAITING: u32 = 5;
const SUSPENDED: u32 = 5;

#[repr(C)]
#[derive(Default)]
struct PowerThrottling {
    version: u32,
    control: u32,
    state: u32,
}

struct Row {
    pid: u32,
    name: String,
    create_time: i64,
    sequence: u64,
    job: u32,
    threads: u32,
    suspended: bool,
}

fn query() -> (Vec<u64>, usize) {
    let mut size = 1 << 20;
    loop {
        let mut buf = vec![0u64; size / 8];
        let mut needed = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SystemFullProcessInformation,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            size = needed as usize + 64 * 1024;
            continue;
        }
        assert!(status >= 0, "NtQuerySystemInformation(148): {status:#x}");
        return (buf, needed as usize);
    }
}

fn rows(buf: &[u64]) -> Vec<Row> {
    let base = buf.as_ptr().cast::<u8>();
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let start = unsafe { base.add(offset) };
        let entry = unsafe { start.cast::<SYSTEM_PROCESS_INFORMATION>().read_unaligned() };
        let threads = unsafe {
            start
                .add(offset_of!(SYSTEM_PROCESS_INFORMATION, Threads))
                .cast::<SYSTEM_EXTENDED_THREAD_INFORMATION>()
        };
        let count = entry.NumberOfThreads as usize;
        let suspended = count > 0
            && (0..count).all(|i| {
                let t = unsafe { threads.add(i).read_unaligned() }.ThreadInfo;
                t.ThreadState == WAITING && t.WaitReason == SUSPENDED
            });
        let extension = unsafe {
            threads
                .add(count)
                .cast::<SYSTEM_PROCESS_INFORMATION_EXTENSION>()
                .read_unaligned()
        };
        let name = if entry.ImageName.Buffer.is_null() {
            String::new()
        } else {
            let units = unsafe {
                std::slice::from_raw_parts(entry.ImageName.Buffer, entry.ImageName.Length as usize / 2)
            };
            String::from_utf16_lossy(units)
        };
        out.push(Row {
            pid: entry.UniqueProcessId as u32,
            name,
            create_time: unsafe { *entry.CreateTime.QuadPart() },
            sequence: extension.ProcessSequenceNumber,
            job: extension.JobObjectId,
            threads: entry.NumberOfThreads,
            suspended,
        });
        if entry.NextEntryOffset == 0 {
            return out;
        }
        offset += entry.NextEntryOffset as usize;
    }
}

fn open(pid: u32) -> Option<HANDLE> {
    let mut handle: HANDLE = null_mut();
    let mut attributes: OBJECT_ATTRIBUTES = unsafe { zeroed() };
    attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    let mut client = CLIENT_ID { UniqueProcess: pid as usize as HANDLE, UniqueThread: null_mut() };
    let status = unsafe {
        NtOpenProcess(&mut handle, PROCESS_QUERY_LIMITED_INFORMATION, &mut attributes, &mut client)
    };
    (status >= 0).then_some(handle)
}

fn info<T: Default>(handle: HANDLE, class: u32) -> Option<T> {
    let mut value = T::default();
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
            null_mut(),
        )
    };
    (status >= 0).then_some(value)
}

fn priority_class(handle: HANDLE) -> Option<u8> {
    let mut value: PROCESS_PRIORITY_CLASS = unsafe { zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_PRIORITY_CLASS_INFO,
            (&mut value as *mut PROCESS_PRIORITY_CLASS).cast(),
            size_of::<PROCESS_PRIORITY_CLASS>() as u32,
            null_mut(),
        )
    };
    (status >= 0).then_some(value.PriorityClass)
}

fn main() {
    let (_, bytes) = query();
    let mut best = f64::MAX;
    let mut total = 0f64;
    let rounds = 50;
    for _ in 0..rounds {
        let started = Instant::now();
        let (buf, _) = query();
        std::hint::black_box(rows(&buf).len());
        let took = started.elapsed().as_secs_f64();
        best = best.min(took);
        total += took;
    }
    let (buf, _) = query();
    let rows = rows(&buf);
    println!(
        "class 148: {} processes, {} threads, {} KiB returned; query+walk best {:.0} us, mean {:.0} us",
        rows.len(),
        rows.iter().map(|r| r.threads).sum::<u32>(),
        bytes / 1024,
        best * 1e6,
        total / rounds as f64 * 1e6,
    );

    for r in rows.iter().filter(|r| r.pid <= 4 || r.sequence == 0 || r.create_time == 0) {
        println!(
            "  pid {:<6} {:<24} sequence {:<6} createTime {} job {}",
            r.pid, r.name, r.sequence, r.create_time, r.job
        );
    }
    let mut sequences: Vec<u64> = rows.iter().map(|r| r.sequence).collect();
    sequences.sort_unstable();
    sequences.dedup();
    println!("distinct sequence numbers: {} of {}", sequences.len(), rows.len());
    println!("in a job: {}", rows.iter().filter(|r| r.job != 0).count());

    let (mut compared, mut mismatched, mut unopened) = (0, 0, 0);
    let mut throttled = Vec::new();
    let handles_started = Instant::now();
    for r in &rows {
        let Some(handle) = open(r.pid) else {
            unopened += 1;
            continue;
        };
        if let Some(sequence) = info::<u64>(handle, PROCESS_SEQUENCE_NUMBER) {
            compared += 1;
            if sequence != r.sequence {
                mismatched += 1;
            }
            if sequence != r.sequence && mismatched <= 5 {
                println!("  sequence mismatch pid {} {}: extension {} handle {sequence}", r.pid, r.name, r.sequence);
            }
        }
        let power = info::<PowerThrottling>(handle, PROCESS_POWER_THROTTLING_STATE);
        let class = priority_class(handle);
        let eco = power.as_ref().is_some_and(|p| p.state & EXECUTION_SPEED != 0);
        let controlled = power.as_ref().is_some_and(|p| p.control & EXECUTION_SPEED != 0);
        if eco || controlled || class == Some(1) {
            throttled.push((r.pid, r.name.clone(), power, class));
        }
        unsafe { NtClose(handle) };
    }
    println!(
        "handle probes: {compared} sequence numbers compared, {mismatched} mismatched, {unopened} not opened, {:.0} us for all",
        handles_started.elapsed().as_secs_f64() * 1e6
    );

    println!("suspended (every thread waiting, reason Suspended):");
    for r in rows.iter().filter(|r| r.suspended) {
        println!("  pid {:<6} {}", r.pid, r.name);
    }

    println!("EcoQoS or idle priority class (class 1 idle, 2 normal, 5 below normal):");
    for (pid, name, power, class) in throttled {
        match power {
            Some(p) => println!(
                "  pid {pid:<6} {name:<32} control {:#x} state {:#x} class {class:?}",
                p.control, p.state
            ),
            None => println!("  pid {pid:<6} {name:<32} power unreadable, class {class:?}"),
        }
    }
}
