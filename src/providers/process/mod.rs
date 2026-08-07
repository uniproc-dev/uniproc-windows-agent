mod events;
mod vars;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use parking_lot::Mutex;

use crate::commands::services::ScManager;
use crate::etw::router::KernelRouterBuilder;
use crate::etw::signatures::utils::parse;
use crate::providers::process::events::{ProcessStartV4Header, ProcessStopData, ThreadTypeGroup1};
use crate::providers::process::vars::*;
use crate::providers::provider::{LivePids, Provider};
use crate::providers::display_name;
use crate::providers::utils::{
    check_signature, enum_service_pids, enum_visible_window_pids, is_windows_process,
    get_process_package_info, parse_cmd_line, query_command_line, query_image_path,
};
use crate::sink::Sink;
use crate::state::events::{ProcessEnriched, ProcessSignature, ProcessStarted, StateChange};

pub use vars::KERNEL_PROCESS_PROVIDER;

/// Resolving a command line is OpenProcess + 3x ReadProcessMemory — far too
/// slow for the shared ETW pump thread (part 3 merged this session's pump
/// with disk/network, so blocking here stalls every other route too).
/// The manifest handler only queues the pid; a dedicated worker thread does
/// the actual (blocking) enrichment and emits a follow-up StateChange.
pub struct KernelProcessProvider {
    tx: Sender<u32>,
    rx: Mutex<Option<Receiver<u32>>>,
    running: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl KernelProcessProvider {
    pub fn new() -> Self {
        Self::with_queue(crossbeam_channel::unbounded())
    }

    /// Shared enrichment queue: bootstrap also feeds pids into it.
    pub fn with_queue((tx, rx): (Sender<u32>, Receiver<u32>)) -> Self {
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            running: Arc::new(AtomicBool::new(false)),
            worker: Mutex::new(None),
        }
    }
}

impl Default for KernelProcessProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything enrich() derives from the image path alone — cached per path:
/// one encode_wide + WinVerifyTrust per unique exe instead of per process.
///
/// `display_name` joins the same cache for the same reason: resolving it
/// parses the binary's version resource, which is far too expensive to redo
/// for every instance of a browser's twenty renderer processes.
#[derive(Clone)]
struct PathVerdict {
    signature: ProcessSignature,
    is_windows_process: bool,
    display_name: String,
}

fn enrich(
    pid: u32,
    verdict_cache: &mut std::collections::HashMap<String, PathVerdict>,
) -> ProcessEnriched {
    // Per-process by nature (different instances of one exe differ), not cached.
    let command_line = unsafe { query_command_line(pid) }
        .map(|s| unsafe { parse_cmd_line(&s) })
        .unwrap_or_default();

    let image_path = unsafe { query_image_path(pid) }.unwrap_or_default();
    // Only needed to resolve a packaged app's manifest name; classic
    // binaries have none and fall through to the version resource.
    let package_full_name = unsafe { get_process_package_info(pid) }
        .map(|(full_name, _)| full_name)
        .unwrap_or_default();
    let is_kernel_process = image_path.is_empty() || !std::path::Path::new(&image_path).exists();

    // A file replaced while its process is alive keeps the stale verdict — fine.
    let verdict = if is_kernel_process {
        // No file to inspect: no signature, no version resource. These are
        // Windows' own pseudo-processes by definition.
        PathVerdict {
            signature: ProcessSignature::Unknown,
            is_windows_process: true,
            display_name: String::new(),
        }
    } else {
        verdict_cache
            .entry(image_path.clone())
            .or_insert_with(|| {
                let signature = check_signature(&image_path);
                PathVerdict {
                    signature,
                    is_windows_process: is_windows_process(false, signature),
                    // Packaged apps are keyed by path here too. That is a
                    // deliberate simplification: one package's executable is
                    // one path, so the manifest lookup would produce the same
                    // answer for every process sharing it.
                    display_name: display_name::resolve(&image_path, &package_full_name)
                        .unwrap_or_default(),
                }
            })
            .clone()
    };

    ProcessEnriched {
        pid,
        command_line,
        image_path,
        display_name: verdict.display_name,
        signature: verdict.signature,
        is_kernel_process,
        is_windows_process: verdict.is_windows_process,
    }
}

/// ETW reports the image as a full NT path (`\Device\HarddiskVolume3\...\
/// foo.exe`), while the bootstrap snapshot reports a bare file name. Left
/// alone, the two sources give the same process different names depending on
/// whether it started before or after the agent did. Everything downstream
/// wants the file name, so normalise here, at the edge.
///
/// Deliberately not translated into a DOS path: nothing needs the directory,
/// and mapping device names to drive letters would mean a `QueryDosDevice`
/// table that can go stale under a mount change.
fn image_file_name(image_name: &str) -> String {
    image_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image_name)
        .to_string()
}

impl Provider for KernelProcessProvider {
    fn register(&self, b: &mut KernelRouterBuilder) -> Result<()> {
        let tx = self.tx.clone();
        b.manifest(KERNEL_PROCESS_PROVIDER)
            .on(&[KERNEL_PROCESS_PROVIDER], move |record, data| {
                let change = match record.EventHeader.EventDescriptor.Id {
                    EVENT_ID_PROCESS_START => {
                        let hdr = parse::<ProcessStartV4Header>(data)?;
                        // Non-blocking: worst case the channel is full/closed
                        // (provider shutting down) and command_line stays empty.
                        let _ = tx.send(hdr.process_id);

                        StateChange::ProcessStarted(ProcessStarted {
                            pid: hdr.process_id,
                            parent_pid: hdr.parent_process_id,
                            session_id: hdr.session_id,
                            image_name: image_file_name(&hdr.image_name.to_string()),
                            package_full_name: hdr.package_full_name.to_string(),
                            package_relative_app_id: hdr.package_relative_app_id.to_string(),
                            command_line: Vec::new(),
                            is_kernel_process: false,
                        })
                    }
                    EVENT_ID_PROCESS_STOP => {
                        let hdr = parse::<ProcessStopData>(data)?;
                        StateChange::ProcessStopped(hdr.process_id)
                    }
                    EVENT_ID_THREAD_START => {
                        let hdr = parse::<ThreadTypeGroup1>(data)?;
                        StateChange::ThreadStarted {
                            pid: hdr.process_id,
                            tid: hdr.thread_id,
                        }
                    }
                    EVENT_ID_THREAD_STOP => {
                        let hdr = parse::<ThreadTypeGroup1>(data)?;
                        StateChange::ThreadStopped { tid: hdr.thread_id }
                    }
                    _ => return None,
                };
                Some(change)
            });
        Ok(())
    }

    fn start(&self, _: LivePids, sink: Sink) -> Result<()> {
        let Some(rx) = self.rx.lock().take() else {
            return Ok(());
        };
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        let handle = std::thread::Builder::new()
            .name("process-enrich".into())
            .spawn(move || {
                let scm = ScManager::open().ok();
                let mut last_inventory = Instant::now() - INVENTORY_INTERVAL;
                let mut verdict_cache = std::collections::HashMap::new();
                let mut services_buf = Vec::new();

                // Timeout, not channel-disconnect: the router-held Sender
                // clone only drops when KernelRouter drops, which happens
                // *after* Supervisor::stop() has already called this stop().
                while running.load(Ordering::Relaxed) {
                    match rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(pid) => sink.emit(StateChange::ProcessEnriched(enrich(
                            pid,
                            &mut verdict_cache,
                        ))),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }

                    if last_inventory.elapsed() >= INVENTORY_INTERVAL {
                        last_inventory = Instant::now();
                        if let Some(scm) = &scm {
                            sink.emit(StateChange::ServicePidsSnapshot(enum_service_pids(
                                scm.handle(),
                                &mut services_buf,
                            )));
                        }
                        sink.emit(StateChange::VisibleWindowPidsSnapshot(
                            enum_visible_window_pids(),
                        ));
                    }
                }
            })?;
        *self.worker.lock() = Some(handle);
        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.worker.lock().take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw::router::KernelRouter;
    use crate::etw::router::tests::ETW_TEST_LOCK;
    use crate::sink::Sink;
    use std::time::{Duration, Instant};

    /// Requires admin and real ETW sessions. Spawns child processes and
    /// expects the manifest route to deliver start/stop events for them.
    /// Run: `cargo test -- --ignored`
    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn process_events_flow_end_to_end() {
        let _guard = ETW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (sink, rx) = Sink::bounded(1024);
        let mut builder = KernelRouter::builder();
        KernelProcessProvider::new()
            .register(&mut builder)
            .unwrap();
        let router = builder.start(sink).expect("router start");

        let mut child = std::process::Command::new("cmd")
            .args(["/c", "exit", "0"])
            .spawn()
            .expect("spawn child");
        let child_pid = child.id();

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut started = false;
        let mut stopped = false;
        while Instant::now() < deadline && !(started && stopped) {
            for change in rx.try_iter() {
                match change {
                    StateChange::ProcessStarted(e) if e.pid == child_pid => started = true,
                    StateChange::ProcessStopped(pid) if pid == child_pid => stopped = true,
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.wait();
        drop(router);

        assert!(started, "no ProcessStarted for child pid {child_pid}");
        assert!(stopped, "no ProcessStopped for child pid {child_pid}");
    }
}
