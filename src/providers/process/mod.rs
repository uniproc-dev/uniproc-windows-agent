mod events;
mod signature_cache;
mod vars;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Instant;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use crate::commands::services::ScManager;
use crate::etw::router::KernelRouterBuilder;
use crate::etw::signatures::utils::parse;
use crate::providers::process::events::{ProcessStartV4Header, ProcessStopData, ThreadTypeGroup1};
use crate::providers::process::vars::*;
use crate::providers::provider::{LivePids, Provider};
use crate::providers::display_name;
use crate::providers::utils::{
    check_signature, enum_services, is_windows_process, query_service_config,
    get_process_package_info, parse_cmd_line, query_command_line, query_console_host_pid,
    query_image_path,
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
    rx: Receiver<u32>,
    signature_store: &'static str,
    running: Arc<AtomicBool>,
    worker: Mutex<Vec<JoinHandle<()>>>,
}

impl KernelProcessProvider {
    pub fn new() -> Self {
        Self::with_queue(crossbeam_channel::unbounded(), crate::providers::SERVICE.signature_store)
    }

    /// Shared enrichment queue: bootstrap also feeds pids into it.
    pub fn with_queue(
        (tx, rx): (Sender<u32>, Receiver<u32>),
        signature_store: &'static str,
    ) -> Self {
        Self {
            tx,
            rx,
            signature_store,
            running: Arc::new(AtomicBool::new(false)),
            worker: Mutex::new(Vec::new()),
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
    persisted: &Option<signature_cache::PersistentSignatures>,
) -> ProcessEnriched {
    // Per-process by nature (different instances of one exe differ), not cached.
    let command_line = unsafe { query_command_line(pid) }
        .map(|s| unsafe { parse_cmd_line(&s) })
        .unwrap_or_default();

    let image_path = unsafe { query_image_path(pid) }.unwrap_or_default();
    // Only needed to resolve a packaged app's manifest name; classic
    // binaries have none and fall through to the version resource.
    let (package_full_name, package_app_id) =
        unsafe { get_process_package_info(pid) }.unwrap_or_default();
    let path_missing = image_path.is_empty() || !std::path::Path::new(&image_path).exists();

    // A file replaced while its process is alive keeps the stale verdict — fine.
    let verdict = if path_missing {
        // No file to inspect: no signature, no version resource. That says
        // nothing about what the process is - kernel pseudo-processes are
        // decided at rundown, and anything else just could not be read.
        PathVerdict {
            signature: ProcessSignature::Unknown,
            is_windows_process: false,
            display_name: String::new(),
        }
    } else {
        let cache = persisted.as_ref().map(|p| p.cache());
        let stamp = signature_cache::file_stamp(&image_path);

        let hit = match (stamp, cache) {
            (Some(stamp), Some(cache)) => cache.lookup(&image_path, stamp),
            _ => None,
        };

        match hit {
            Some(hit) => PathVerdict {
                signature: signature_cache::signature_from_code(hit.signature),
                is_windows_process: hit.is_windows_process,
                display_name: hit.display_name,
            },
            None => {
                let signature = signature_of(&image_path, &package_full_name);
                let verdict = PathVerdict {
                    signature,
                    is_windows_process: is_windows_process(false, signature),
                    // Packaged apps are keyed by path here too, which assumes
                    // one application per executable. A package that runs
                    // several applications from one exe would show the first
                    // one's name for all of them.
                    display_name: display_name::resolve(
                        &image_path,
                        &package_full_name,
                        &package_app_id,
                    )
                    .unwrap_or_default(),
                };

                if let (Some(stamp), Some(cache)) = (stamp, cache) {
                    cache.remember(
                        &image_path,
                        signature_cache::CachedVerdict {
                            signature: signature_cache::signature_to_code(verdict.signature),
                            is_windows_process: verdict.is_windows_process,
                            display_name: verdict.display_name.clone(),
                            size: stamp.0,
                            modified_ms: stamp.1,
                            resolver: signature_cache::RESOLVER,
                        },
                    );
                }

                verdict
            }
        }
    };

    ProcessEnriched {
        pid,
        command_line,
        image_path,
        display_name: verdict.display_name,
        signature: verdict.signature,
        is_windows_process: verdict.is_windows_process,
        console_host_pid: unsafe { query_console_host_pid(pid) },
    }
}

/// The signature verdict for one image.
///
/// Files inside an MSIX package carry no signature of their own - the
/// package is signed as a whole - so per-file verification honestly reports
/// them unsigned. For those, the package publisher is the signer, and it is
/// one the OS already validated at install time.
fn signature_of(image_path: &str, package_full_name: &str) -> ProcessSignature {
    let signature = check_signature(image_path);
    if signature != ProcessSignature::Unsigned || package_full_name.is_empty() {
        return signature;
    }

    match display_name::package_publisher(package_full_name) {
        Some(publisher) if publisher.contains("Microsoft") => ProcessSignature::Microsoft,
        Some(_) => ProcessSignature::ThirdParty,
        None => signature,
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

                        StateChange::ProcessStarted(Box::new(ProcessStarted {
                            pid: hdr.process_id,
                            parent_pid: hdr.parent_process_id,
                            session_id: hdr.session_id,
                            image_name: image_file_name(&hdr.image_name.to_string()),
                            package_full_name: hdr.package_full_name.to_string(),
                            package_relative_app_id: hdr.package_relative_app_id.to_string(),
                            command_line: Vec::new(),
                            is_kernel_process: false,
                        }))
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
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let rx = self.rx.clone();

        let persisted = signature_cache::open(self.signature_store);
        let mut handles = Vec::with_capacity(2);

        {
            let running = self.running.clone();
            let sink = sink.clone();

            handles.push(
                std::thread::Builder::new()
                    .name("process-enrich".into())
                    .spawn(move || {
                        while let Ok(pid) = rx.recv() {
                            if !running.load(Ordering::Relaxed) {
                                break;
                            }
                            sink.emit(StateChange::ProcessEnriched(Box::new(enrich(
                                pid, &persisted,
                            ))));
                        }
                    })?,
            );
        }

        let running = self.running.clone();
        handles.push(
            std::thread::Builder::new()
                .name("service-inventory".into())
                .spawn(move || {
                    let scm = ScManager::open().ok();
                    let mut services_buf = Vec::new();
                    let mut config_cache: std::collections::HashMap<String, _> =
                        std::collections::HashMap::new();

                    while running.load(Ordering::Relaxed) {
                        if let Some(scm) = &scm {
                            let mut services = enum_services(scm.handle(), &mut services_buf);
                            for svc in &mut services {
                                let config =
                                    config_cache.entry(svc.name.clone()).or_insert_with(|| {
                                        query_service_config(scm.handle(), &svc.name)
                                    });
                                svc.load_group = config.load_group.clone();
                                svc.description = config.description.clone();
                                svc.image_path = config.image_path.clone();
                            }
                            config_cache
                                .retain(|name, _| services.iter().any(|s| &s.name == name));
                            sink.emit(StateChange::ServicesSnapshot(services));
                        }
                        crate::settings::park_while(&running, Instant::now() + INVENTORY_INTERVAL);
                    }
                })?,
        );

        *self.worker.lock() = handles;
        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.tx.send(WAKE_PID);
        for handle in self.worker.lock().drain(..) {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

const WAKE_PID: u32 = u32::MAX;

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
