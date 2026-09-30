pub mod passport;
mod signature_cache;

use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use smol_str::SmolStr;

use crate::providers::display_name;
use crate::providers::process::passport::{Passport, SidNames};
use crate::providers::utils::{
    check_signer, get_process_package_info, is_windows_process, parse_cmd_line,
    query_command_line, query_console_host_pid, query_image_path, query_sequence_number,
};
use crate::state::events::{Image, ImageVerdict, ProcessSignature};
use crate::win::OwnedProcess;
use windows::Win32::PROCESS_QUERY_LIMITED_INFORMATION;

/// What one process's handle, memory and token tell, read the moment a
/// snapshot first lists it.
#[derive(Clone, Debug, Default)]
pub struct ProcessRead {
    pub command_line: Vec<String>,
    pub image_path: SmolStr,
    pub package_full_name: SmolStr,
    pub package_relative_app_id: SmolStr,
    /// Pid of the conhost serving the console, 0 for none.
    pub console_host_pid: u32,
    pub passport: Passport,
}

/// Reads `pid` through one limited-query handle, and nothing when the
/// handle belongs to another process than the snapshot's `sequence_number`.
/// `user_sid` and `package` are what the snapshot recorded; the process's
/// own answer about its package wins.
pub fn read(
    pid: u32,
    sequence_number: u64,
    user_sid: Option<&[u8]>,
    package: (String, String),
    names: &mut SidNames,
) -> ProcessRead {
    let process = OwnedProcess::open(PROCESS_QUERY_LIMITED_INFORMATION, pid)
        .ok()
        .filter(|p| unsafe { query_sequence_number(p.0) }.is_none_or(|n| n == sequence_number));
    let handle = process.as_ref().map(|p| p.0);
    let command_line = handle
        .and_then(|h| unsafe { query_command_line(h) })
        .map(|s| unsafe { parse_cmd_line(&s) })
        .unwrap_or_default();
    let image_path = handle.and_then(|h| unsafe { query_image_path(h) }).unwrap_or_default();
    let (package_full_name, package_relative_app_id) =
        handle.and_then(|h| unsafe { get_process_package_info(h) }).unwrap_or(package);
    let passport = passport::probe(handle, user_sid, !package_full_name.is_empty(), names);
    ProcessRead {
        command_line,
        image_path: image_path.into(),
        package_full_name: package_full_name.into(),
        package_relative_app_id: package_relative_app_id.into(),
        console_host_pid: handle.map_or(0, |h| unsafe { query_console_host_pid(h) }),
        passport,
    }
}

/// An image the model has no verdict for yet.
#[derive(Clone, Debug, Default)]
pub struct ImageRequest {
    pub path: SmolStr,
    pub package_full_name: SmolStr,
    pub package_relative_app_id: SmolStr,
}

/// Judges images on a thread of its own: verifying a signature and reading
/// a version resource take far too long for the tick. Every verdict
/// persists per path and file stamp, so a restart finds most of them at
/// once. No verdict is lost; the thread stops when this is dropped.
pub struct Images {
    requests: Sender<ImageRequest>,
    verdicts: Receiver<Image>,
    worker: Option<JoinHandle<()>>,
}

impl Images {
    /// `wake` is called after every verdict.
    pub fn start(signature_store: &str, wake: impl Fn() + Send + 'static) -> Result<Self> {
        let (requests, asked) = crossbeam_channel::unbounded::<ImageRequest>();
        let (judged, verdicts) = crossbeam_channel::unbounded();
        let persisted = signature_cache::open(signature_store);
        let worker = std::thread::Builder::new()
            .name("image-judge".into())
            .spawn(move || {
                for request in asked.iter().take_while(|request| !request.path.is_empty()) {
                    let verdict = judge(&request, persisted.as_ref());
                    if judged.send(Image { path: request.path, verdict }).is_err() {
                        break;
                    }
                    wake();
                }
            })?;
        Ok(Self {
            requests,
            verdicts,
            worker: Some(worker),
        })
    }

    pub fn ask(&self, request: ImageRequest) {
        let _ = self.requests.send(request);
    }

    /// The verdicts that came in since the last call.
    pub fn judged(&self) -> impl Iterator<Item = Image> + '_ {
        self.verdicts.try_iter()
    }

    /// The next verdict, if one comes within `timeout`.
    pub fn next(&self, timeout: Duration) -> Option<Image> {
        self.verdicts.recv_timeout(timeout).ok()
    }
}

impl Drop for Images {
    fn drop(&mut self) {
        let _ = self.requests.send(ImageRequest::default());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(path = %request.path))]
fn judge(request: &ImageRequest, persisted: Option<&signature_cache::PersistentSignatures>) -> ImageVerdict {
    let path = &request.path;
    if !std::path::Path::new(path).exists() {
        return ImageVerdict::default();
    }
    let stamp = signature_cache::file_stamp(path);
    let cache = persisted.map(|p| p.cache());
    let hit = match (stamp, cache) {
        (Some(stamp), Some(cache)) => cache.lookup(path, stamp),
        _ => None,
    };
    let (signature, is_windows, display_name, signer) = match hit {
        Some(hit) => (
            signature_cache::signature_from_code(hit.signature),
            hit.is_windows_process,
            hit.display_name,
            hit.signer,
        ),
        None => {
            let (signature, signer) = signature_of(path, &request.package_full_name);
            let is_windows = is_windows_process(false, signature);
            let display_name =
                display_name::resolve(path, &request.package_full_name, &request.package_relative_app_id)
                    .unwrap_or_default();
            let signer = signer.unwrap_or_default();
            if let (Some(stamp), Some(cache)) = (stamp, cache) {
                cache.remember(
                    path,
                    signature_cache::CachedVerdict {
                        signature: signature_cache::signature_to_code(signature),
                        is_windows_process: is_windows,
                        display_name: display_name.clone(),
                        signer: signer.clone(),
                        size: stamp.0,
                        modified_ms: stamp.1,
                        resolver: signature_cache::RESOLVER,
                    },
                );
            }
            (signature, is_windows, display_name, signer)
        }
    };
    let publisher = if request.package_full_name.is_empty() {
        signer
    } else {
        display_name::package_publisher_display_name(&request.package_full_name).unwrap_or_default()
    };
    ImageVerdict {
        signature,
        is_windows_process: is_windows,
        display_name: display_name.into(),
        publisher: publisher.into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_reads_its_own_passport() {
        let me = unsafe { query_sequence_number(windows::Win32::GetCurrentProcess()) }.expect("sequence number");
        let read = read(std::process::id(), me, None, Default::default(), &mut SidNames::default());
        assert!(read.image_path.ends_with(".exe"), "{}", read.image_path);
        assert_eq!(read.command_line, std::env::args().collect::<Vec<_>>());
        assert!(read.passport.user.contains('\\'));
        assert_ne!(read.passport.architecture, crate::model::Architecture::Unknown);
    }

    #[test]
    #[ignore = "requires admin"]
    fn the_services_of_system_read_with_a_limited_handle() {
        crate::privileges::enable(windows::core::w!("SeDebugPrivilege")).unwrap();
        let mut processes = crate::snapshot::Processes::new();
        processes.read().expect("elevated");
        let mut names = SidNames::default();
        let lines: Vec<Vec<String>> = processes
            .rows()
            .iter()
            .filter(|row| processes.image_name(row).eq_ignore_ascii_case("svchost.exe"))
            .map(|row| read(row.pid, row.sequence_number, None, Default::default(), &mut names).command_line)
            .collect();
        assert!(lines.len() > 5, "{} svchosts", lines.len());
        let read = lines.iter().filter(|line| line.iter().any(|arg| arg == "-k")).count();
        assert!(read * 2 > lines.len(), "{read} of {} svchost command lines read", lines.len());
    }

    #[test]
    fn a_handle_to_another_process_than_the_listed_one_reads_nothing() {
        let me = unsafe { query_sequence_number(windows::Win32::GetCurrentProcess()) }.expect("sequence number");
        let package = ("listed".to_string(), "app".to_string());
        let read = read(std::process::id(), me + 1, None, package, &mut SidNames::default());
        assert!(read.image_path.is_empty() && read.command_line.is_empty());
        assert_eq!(read.package_full_name, "listed");
        assert_eq!(read.passport.architecture, crate::model::Architecture::Unknown);
    }

    #[test]
    fn every_image_asked_for_is_judged_and_wakes_the_asker() {
        let (woken, wakes) = crossbeam_channel::unbounded();
        let images = Images::start("signatures-images-test", move || {
            let _ = woken.send(());
        })
        .unwrap();
        for path in [r"C:\no\such\a.exe", r"C:\no\such\b.exe"] {
            images.ask(ImageRequest {
                path: path.into(),
                ..Default::default()
            });
        }
        let mut judged: Vec<SmolStr> = (0..2)
            .map(|_| images.next(Duration::from_secs(5)).expect("a verdict").path)
            .collect();
        judged.sort();
        assert_eq!(judged, [r"C:\no\such\a.exe", r"C:\no\such\b.exe"]);
        for _ in 0..2 {
            wakes.recv_timeout(Duration::from_secs(5)).expect("a wake per verdict");
        }
        assert!(wakes.try_recv().is_err(), "no more wakes than verdicts");
    }

    #[test]
    fn an_image_that_is_gone_has_no_verdict() {
        let request = ImageRequest {
            path: r"C:\no\such\image.exe".into(),
            ..Default::default()
        };
        assert_eq!(judge(&request, None), ImageVerdict::default());
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
