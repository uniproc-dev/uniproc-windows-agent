pub mod passport;
mod signature_cache;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use crate::providers::display_name;
use crate::providers::process::passport::SidNames;
use crate::providers::provider::Provider;
use crate::providers::utils::{
    check_signer, get_process_package_info, is_windows_process, parse_cmd_line,
    query_command_line, query_console_host_pid, query_image_path,
};
use crate::sink::Sink;
use crate::state::events::{EnrichRequest, ProcessEnriched, ProcessSignature, StateChange};

/// Reads what a process's passport needs off the tick's thread: opening the
/// process, its memory and its image file is far too slow to do there. The
/// tick queues each process it sees for the first time, and the worker sends
/// back a follow-up change.
pub struct Enricher {
    tx: Sender<EnrichRequest>,
    rx: Receiver<EnrichRequest>,
    signature_store: String,
    running: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Enricher {
    pub fn new(signature_store: String) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        Self {
            tx,
            rx,
            signature_store,
            running: Arc::new(AtomicBool::new(false)),
            worker: Mutex::new(None),
        }
    }

    /// Where the tick queues the processes it sees for the first time.
    pub fn queue(&self) -> Sender<EnrichRequest> {
        self.tx.clone()
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
    signer: String,
}

fn enrich(
    request: &EnrichRequest,
    persisted: &Option<signature_cache::PersistentSignatures>,
    names: &mut SidNames,
) -> ProcessEnriched {
    let pid = request.pid;
    // Per-process by nature (different instances of one exe differ), not cached.
    let command_line = unsafe { query_command_line(pid) }
        .map(|s| unsafe { parse_cmd_line(&s) })
        .unwrap_or_default();

    let image_path = unsafe { query_image_path(pid) }.unwrap_or_default();
    let (package_full_name, package_app_id) = match unsafe { get_process_package_info(pid) } {
        Some(package) => package,
        None => (request.package_full_name.clone(), request.package_relative_app_id.clone()),
    };
    let path_missing = image_path.is_empty() || !std::path::Path::new(&image_path).exists();

    // A file replaced while its process is alive keeps the stale verdict — fine.
    let verdict = if path_missing {
        PathVerdict {
            signature: ProcessSignature::Unknown,
            is_windows_process: false,
            display_name: String::new(),
            signer: String::new(),
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
                signer: hit.signer,
            },
            None => {
                let (signature, signer) = signature_of(&image_path, &package_full_name);
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
                    signer: signer.unwrap_or_default(),
                };

                if let (Some(stamp), Some(cache)) = (stamp, cache) {
                    cache.remember(
                        &image_path,
                        signature_cache::CachedVerdict {
                            signature: signature_cache::signature_to_code(verdict.signature),
                            is_windows_process: verdict.is_windows_process,
                            display_name: verdict.display_name.clone(),
                            signer: verdict.signer.clone(),
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

    let publisher = if package_full_name.is_empty() {
        verdict.signer
    } else {
        display_name::package_publisher_display_name(&package_full_name).unwrap_or_default()
    };
    let passport = passport::probe(
        pid,
        request.user_sid.as_deref(),
        !package_full_name.is_empty(),
        names,
    );

    ProcessEnriched {
        pid,
        sequence_number: request.sequence_number,
        command_line,
        image_path,
        package_full_name,
        package_relative_app_id: package_app_id,
        display_name: verdict.display_name,
        signature: verdict.signature,
        is_windows_process: verdict.is_windows_process,
        console_host_pid: unsafe { query_console_host_pid(pid) },
        publisher,
        passport,
    }
}

/// The signature verdict for one image, and who signed it.
///
/// Files inside an MSIX package carry no signature of their own - the
/// package is signed as a whole - so per-file verification honestly reports
/// them unsigned. For those, the package publisher is the signer, and it is
/// one the OS already validated at install time.
fn signature_of(image_path: &str, package_full_name: &str) -> (ProcessSignature, Option<String>) {
    let (signature, signer) = check_signer(image_path);
    if signature != ProcessSignature::Unsigned || package_full_name.is_empty() {
        return (signature, signer);
    }

    match display_name::package_publisher(package_full_name) {
        Some(publisher) if publisher.contains("Microsoft") => (ProcessSignature::Microsoft, None),
        Some(_) => (ProcessSignature::ThirdParty, None),
        None => (signature, signer),
    }
}

impl Provider for Enricher {
    fn start(&self, sink: Sink) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let rx = self.rx.clone();

        let persisted = signature_cache::open(&self.signature_store);
        let running = self.running.clone();
        let worker = std::thread::Builder::new()
            .name("process-enrich".into())
            .spawn(move || {
                let mut names = SidNames::default();
                while let Ok(request) = rx.recv() {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    sink.emit(StateChange::ProcessEnriched(Box::new(enrich(
                        &request,
                        &persisted,
                        &mut names,
                    ))));
                }
            })?;

        *self.worker.lock() = Some(worker);
        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.tx.send(EnrichRequest::default());
        if let Some(worker) = self.worker.lock().take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_enriched_with_its_passport() {
        let request = EnrichRequest {
            pid: std::process::id(),
            sequence_number: 7,
            ..Default::default()
        };
        let enriched = enrich(&request, &None, &mut SidNames::default());
        assert_eq!(enriched.sequence_number, 7);
        assert!(enriched.image_path.ends_with(".exe"), "{}", enriched.image_path);
        assert!(!enriched.command_line.is_empty());
        assert!(enriched.passport.user.contains('\\'));
        assert_ne!(enriched.passport.architecture, crate::model::Architecture::Unknown);
    }

    #[test]
    fn a_windows_binary_names_microsoft_as_its_publisher() {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
        let (signature, signer) = signature_of(&format!(r"{system_root}\System32\notepad.exe"), "");
        if signature == ProcessSignature::Microsoft {
            assert!(signer.is_some_and(|s| s.contains("Microsoft")));
        }
    }
}
