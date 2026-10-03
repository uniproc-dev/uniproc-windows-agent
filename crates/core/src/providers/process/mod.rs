pub mod passport;
mod signature_cache;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::bindings::{DRIVE_REMOTE, GetDriveTypeW, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_core::PCWSTR;

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
/// once. The thread stops when this is dropped, after the image it is
/// judging; the requests still queued are left.
pub struct Images {
    requests: Sender<ImageRequest>,
    verdicts: Receiver<Image>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Images {
    /// `wake` is called after every verdict.
    pub fn start(signature_store: &str, wake: impl Fn() + Send + 'static) -> Result<Self> {
        let (requests, asked) = crossbeam_channel::unbounded::<ImageRequest>();
        let (judged, verdicts) = crossbeam_channel::unbounded();
        let persisted = signature_cache::open(signature_store);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::Builder::new()
            .name("image-judge".into())
            .spawn(move || {
                let mut judged_before = Judged::default();
                for request in asked.iter().take_while(|_| !stopped.load(Ordering::Relaxed)) {
                    let verdict = judge(&request, persisted.as_ref(), &mut judged_before);
                    if judged.send(Image { path: request.path, verdict }).is_err() {
                        break;
                    }
                    wake();
                }
            })?;
        Ok(Self {
            requests,
            verdicts,
            stop,
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
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.requests.send(ImageRequest::default());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The verdicts this run worked out, each with the stamp of the file it
/// describes.
type Judged = std::collections::HashMap<SmolStr, (signature_cache::Stamp, ImageVerdict)>;

#[tracing::instrument(level = "debug", skip_all, fields(path = %request.path))]
fn judge(
    request: &ImageRequest,
    persisted: Option<&signature_cache::PersistentSignatures>,
    judged_before: &mut Judged,
) -> ImageVerdict {
    let path = &request.path;
    if is_remote(path) || !std::path::Path::new(path).exists() {
        return ImageVerdict::default();
    }
    let stamp = signature_cache::file_stamp(path);
    if let Some(stamp) = stamp
        && let Some((before, verdict)) = judged_before.get(path)
        && *before == stamp
    {
        return verdict.clone();
    }
    let verdict = judge_afresh(request, stamp, persisted);
    if let Some(stamp) = stamp {
        judged_before.insert(path.clone(), (stamp, verdict.clone()));
    }
    verdict
}

fn judge_afresh(
    request: &ImageRequest,
    stamp: Option<signature_cache::Stamp>,
    persisted: Option<&signature_cache::PersistentSignatures>,
) -> ImageVerdict {
    let path = &request.path;
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
                        size: stamp.size,
                        modified_ms: stamp.modified_ms,
                        resolver: signature_cache::RESOLVER,
                        file_id: stamp.file_id,
                        usn: stamp.usn,
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

/// Whether `path` names a file on another machine. The service would open it
/// with the machine's own account, so it is never opened at all.
fn is_remote(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\\?\").or_else(|| lower.strip_prefix(r"\\.\")) {
        return rest.starts_with(r"unc\") || rest.starts_with(r"globalroot\device\mup");
    }
    if lower.starts_with(r"\\") || lower.starts_with(r"\device\mup") {
        return true;
    }
    match lower.as_bytes() {
        [letter, b':', ..] if letter.is_ascii_alphabetic() => {
            let root: Vec<u16> = [*letter as u16, b':' as u16, b'\\' as u16, 0].into();
            unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) == DRIVE_REMOTE as u32 }
        }
        _ => false,
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

    match package_signature(package_full_name) {
        Some(signature) => (signature, None),
        None => (signature, signer),
    }
}

fn package_signature(package_full_name: &str) -> Option<ProcessSignature> {
    let publisher = display_name::package_publisher(package_full_name)?;
    let microsoft = MICROSOFT_PUBLISHERS.contains(&publisher.as_str())
        && display_name::package_from_windows_or_store(package_full_name);
    Some(if microsoft { ProcessSignature::Microsoft } else { ProcessSignature::ThirdParty })
}

const MICROSOFT_PUBLISHERS: [&str; 2] = [
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_on_another_machine_is_remote() {
        for remote in [
            r"\\host\share\a.exe",
            r"\\?\UNC\host\share\a.exe",
            r"\\.\UNC\host\share\a.exe",
            r"\Device\Mup\host\share\a.exe",
            r"\\?\GLOBALROOT\Device\Mup\host\share\a.exe",
        ] {
            assert!(is_remote(remote), "{remote}");
        }
        for local in [r"C:\Windows\explorer.exe", r"\\?\C:\Windows\explorer.exe", r"\\.\C:\x.exe", "Registry"] {
            assert!(!is_remote(local), "{local}");
        }
    }

    #[test]
    fn a_remote_image_is_judged_without_being_opened() {
        let verdict = judge(
            &ImageRequest {
                path: r"\\uniproc-no-such-host.invalid\share\a.exe".into(),
                ..Default::default()
            },
            None,
            &mut Judged::default(),
        );
        assert_eq!(verdict.signature, ProcessSignature::Unknown);
    }

    #[test]
    fn this_process_reads_its_own_passport() {
        let me = unsafe { query_sequence_number(crate::bindings::GetCurrentProcess()) }.expect("sequence number");
        let read = read(std::process::id(), me, None, Default::default(), &mut SidNames::default());
        assert!(read.image_path.ends_with(".exe"), "{}", read.image_path);
        assert_eq!(read.command_line, std::env::args().collect::<Vec<_>>());
        assert!(read.passport.user.contains('\\'));
        assert_ne!(read.passport.architecture, crate::model::Architecture::Unknown);
    }

    #[test]
    #[ignore = "requires admin"]
    fn the_services_of_system_read_with_a_limited_handle() {
        crate::privileges::enable(windows_core::w!("SeDebugPrivilege")).unwrap();
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
        let me = unsafe { query_sequence_number(crate::bindings::GetCurrentProcess()) }.expect("sequence number");
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
        assert_eq!(judge(&request, None, &mut Judged::default()), ImageVerdict::default());
    }

    #[test]
    fn an_installed_microsoft_package_is_microsoft() {
        let packages = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-AppxPackage -Publisher 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' | Select-Object -First 1).PackageFullName"])
            .output()
            .expect("powershell");
        let full_name = String::from_utf8_lossy(&packages.stdout).trim().to_string();
        if full_name.is_empty() {
            return;
        }
        assert_eq!(package_signature(&full_name), Some(ProcessSignature::Microsoft), "{full_name}");
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
