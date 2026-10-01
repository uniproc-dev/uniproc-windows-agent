use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};
use smol_str::SmolStr;

use crate::model::{Architecture, DpiAwareness, Isolation, Mitigations, ProcessState, UacVirtualization};
use crate::providers::process::{ImageRequest, ProcessRead};
use crate::report::{self, Diff};
use crate::snapshot::Row;
use crate::state::events::{Image, ImageVerdict, ProcessSignature};

/// What a process is when the snapshot first lists it: the row's own facts
/// and what its handle and token tell.
#[derive(Clone, Debug, Default)]
pub struct Sighted {
    pub image_name: SmolStr,
    pub is_kernel_process: bool,
    pub read: ProcessRead,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub sequence_number: u64,
    /// FILETIME.
    pub start_time: u64,
    pub image_name: SmolStr,
    pub image_path: SmolStr,
    /// From the image's verdict; empty until it comes, and when nothing answered.
    pub display_name: SmolStr,
    pub command_line: Arc<[String]>,
    pub package_name: SmolStr,
    pub package_relative_app_id: SmolStr,

    pub signature: ProcessSignature,
    pub is_kernel_process: bool,
    pub is_windows_process: bool,
    pub console_host_pid: u32,

    pub user: SmolStr,
    pub architecture: Architecture,
    pub elevated: Option<bool>,
    pub uac_virtualization: UacVirtualization,
    pub isolation: Isolation,
    pub dpi_awareness: DpiAwareness,
    pub mitigations: Option<Mitigations>,
    pub publisher: SmolStr,

    /// As the last sample saw it.
    pub state: ProcessState,
    /// The reconcile that last found it listed.
    pub(crate) listed: u64,
}

impl ProcessEntry {
    fn sighted(row: &Row, sighted: Sighted) -> Self {
        let read = sighted.read;
        let passport = read.passport;
        Self {
            pid: row.pid,
            parent_pid: row.parent_pid,
            session_id: row.session_id,
            sequence_number: row.sequence_number,
            start_time: row.create_time,
            image_name: sighted.image_name,
            image_path: read.image_path,
            display_name: SmolStr::default(),
            command_line: read.command_line.into(),
            package_name: read.package_full_name,
            package_relative_app_id: read.package_relative_app_id,
            signature: ProcessSignature::Unknown,
            is_kernel_process: sighted.is_kernel_process,
            is_windows_process: sighted.is_kernel_process,
            console_host_pid: read.console_host_pid,
            user: passport.user,
            architecture: passport.architecture,
            elevated: passport.elevated,
            uac_virtualization: passport.uac_virtualization,
            isolation: passport.isolation,
            dpi_awareness: passport.dpi_awareness,
            mitigations: passport.mitigations,
            publisher: SmolStr::default(),
            state: ProcessState {
                pid: row.pid,
                sequence_number: row.sequence_number,
                ..Default::default()
            },
            listed: 0,
        }
    }

    fn judged(&mut self, verdict: &ImageVerdict) -> bool {
        let is_windows_process = self.is_kernel_process || verdict.is_windows_process;
        let moved = self.signature != verdict.signature
            || self.is_windows_process != is_windows_process
            || self.display_name != verdict.display_name
            || self.publisher != verdict.publisher;
        self.signature = verdict.signature;
        self.is_windows_process = is_windows_process;
        self.display_name = verdict.display_name.clone();
        self.publisher = verdict.publisher.clone();
        moved
    }
}

/// An image some listed process runs: its verdict once judged, and how
/// many listed processes run it.
struct Running {
    verdict: Option<ImageVerdict>,
    processes: u32,
}

/// The processes the last snapshot listed, keyed by pid, the verdicts on
/// the images they run, and what changed since the last [`take`](Self::take).
pub struct ProcessTable {
    processes: FxHashMap<u32, ProcessEntry>,
    images: FxHashMap<SmolStr, Running>,
    reconciled: u64,
    gone: Vec<(u32, u64)>,
    passports: FxHashSet<u32>,
    states: FxHashSet<u32>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            processes: FxHashMap::default(),
            images: FxHashMap::default(),
            reconciled: 0,
            gone: Vec::new(),
            passports: FxHashSet::default(),
            states: FxHashSet::default(),
        }
    }

    /// Makes the table exactly the snapshot's processes: a pid whose sequence
    /// number moved is a new process, read by `sight` as it joins. Hands
    /// `ask` each image nobody asked a verdict for yet.
    pub fn reconcile(
        &mut self,
        rows: &[Row],
        mut sight: impl FnMut(&Row) -> Sighted,
        mut ask: impl FnMut(ImageRequest),
    ) {
        self.reconciled += 1;
        let now = self.reconciled;
        for row in rows {
            if let Some(entry) = self.processes.get_mut(&row.pid)
                && entry.sequence_number == row.sequence_number
            {
                entry.listed = now;
                continue;
            }
            let mut entry = ProcessEntry::sighted(row, sight(row));
            entry.listed = now;
            if !entry.image_path.is_empty() {
                match self.images.get_mut(&entry.image_path) {
                    Some(running) => {
                        running.processes += 1;
                        if let Some(verdict) = &running.verdict {
                            entry.judged(verdict);
                        }
                    }
                    None => {
                        self.images.insert(
                            entry.image_path.clone(),
                            Running {
                                verdict: None,
                                processes: 1,
                            },
                        );
                        ask(ImageRequest {
                            path: entry.image_path.clone(),
                            package_full_name: entry.package_name.clone(),
                            package_relative_app_id: entry.package_relative_app_id.clone(),
                        });
                    }
                }
            }
            if let Some(earlier) = self.processes.insert(row.pid, entry) {
                self.gone.push((row.pid, earlier.sequence_number));
                release(&mut self.images, &earlier.image_path);
            }
            self.passports.insert(row.pid);
            self.states.insert(row.pid);
        }

        let (images, gone, passports, states) = (&mut self.images, &mut self.gone, &mut self.passports, &mut self.states);
        self.processes.retain(|pid, entry| {
            let stays = entry.listed == now;
            if !stays {
                gone.push((*pid, entry.sequence_number));
                passports.remove(pid);
                states.remove(pid);
                release(images, &entry.image_path);
            }
            stays
        });
    }

    /// Hands the verdict to every process running the image; a verdict on
    /// an image nobody runs any more is dropped.
    pub fn judge(&mut self, image: Image) {
        let Some(running) = self.images.get_mut(&image.path) else {
            return;
        };
        for entry in self.processes.values_mut().filter(|e| e.image_path == image.path) {
            if entry.judged(&image.verdict) {
                self.passports.insert(entry.pid);
            }
        }
        running.verdict = Some(image.verdict);
    }

    /// Records a process's state as a sample saw it.
    pub fn observe(&mut self, state: ProcessState) {
        let Some(entry) = self.processes.get_mut(&state.pid) else {
            return;
        };
        if entry.sequence_number == state.sequence_number && entry.state != state {
            entry.state = state;
            self.states.insert(state.pid);
        }
    }

    /// Adds what changed since the last call to `diff`, in no order.
    pub fn take(&mut self, diff: &mut Diff) {
        let processes = &self.processes;
        diff.gone.append(&mut self.gone);
        diff.passports
            .extend(self.passports.drain().filter_map(|pid| processes.get(&pid)).map(report::passport));
        diff.states
            .extend(self.states.drain().filter_map(|pid| processes.get(&pid)).map(|e| e.state));
    }

    /// The images asked for and not judged yet.
    pub fn pending(&self) -> impl Iterator<Item = &str> {
        self.images
            .iter()
            .filter(|(_, running)| running.verdict.is_none())
            .map(|(path, _)| path.as_str())
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.get(&pid)
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

fn release(images: &mut FxHashMap<SmolStr, Running>, path: &str) {
    if let Some(running) = images.get_mut(path) {
        running.processes -= 1;
        if running.processes == 0 {
            images.remove(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::process::passport::Passport;

    fn row(pid: u32, sequence_number: u64) -> Row {
        Row {
            pid,
            sequence_number,
            ..Default::default()
        }
    }

    fn running(image: &'static str) -> impl FnMut(&Row) -> Sighted {
        move |row| Sighted {
            image_name: format!("p{}.exe", row.pid).into(),
            read: ProcessRead {
                image_path: image.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn table(rows: &[Row], image: &'static str) -> ProcessTable {
        let mut t = ProcessTable::new();
        sync(&mut t, rows, image);
        taken(&mut t);
        t
    }

    fn sync(t: &mut ProcessTable, rows: &[Row], image: &'static str) -> Vec<ImageRequest> {
        let mut asked = Vec::new();
        t.reconcile(rows, running(image), |request| asked.push(request));
        asked
    }

    fn taken(t: &mut ProcessTable) -> Diff {
        let mut diff = Diff::default();
        t.take(&mut diff);
        diff.passports.sort_unstable_by_key(|p| p.pid);
        diff.states.sort_unstable_by_key(|s| s.pid);
        diff
    }

    fn verdict(path: &str, display_name: &str) -> Image {
        Image {
            path: path.into(),
            verdict: ImageVerdict {
                signature: ProcessSignature::ThirdParty,
                display_name: display_name.into(),
                publisher: "Contoso".into(),
                ..Default::default()
            },
        }
    }

    fn paths(requests: &[ImageRequest]) -> Vec<&str> {
        requests.iter().map(|r| r.path.as_str()).collect()
    }

    fn pids(diff: &Diff) -> (Vec<u32>, Vec<u32>) {
        (
            diff.passports.iter().map(|p| p.pid).collect(),
            diff.states.iter().map(|s| s.pid).collect(),
        )
    }

    #[test]
    fn the_table_becomes_exactly_the_snapshot() {
        let mut t = table(&[row(100, 1), row(200, 2)], "a.exe");
        sync(&mut t, &[row(200, 2), row(300, 3)], "a.exe");
        let listed: Vec<bool> = [100, 200, 300].iter().map(|&pid| t.get(pid).is_some()).collect();
        assert_eq!(listed, [false, true, true]);
    }

    #[test]
    fn a_process_joining_sends_its_passport_and_its_state() {
        let mut t = ProcessTable::new();
        sync(&mut t, &[row(200, 2), row(100, 1)], "a.exe");
        let diff = taken(&mut t);
        assert_eq!(pids(&diff), (vec![100, 200], vec![100, 200]));
        assert!(diff.gone.is_empty());
        assert_eq!((diff.states[0].pid, diff.states[0].sequence_number), (100, 1));
    }

    #[test]
    fn a_process_leaving_is_sent_as_gone() {
        let mut t = table(&[row(100, 1), row(200, 2)], "a.exe");
        sync(&mut t, &[row(100, 1)], "a.exe");
        let diff = taken(&mut t);
        assert_eq!(diff.gone, [(200, 2)]);
        assert_eq!(pids(&diff), (vec![], vec![]));
    }

    #[test]
    fn a_reused_pid_is_one_process_gone_and_another_joined() {
        let mut t = table(&[row(100, 1)], "a.exe");
        t.judge(verdict("a.exe", "Old"));
        taken(&mut t);
        sync(&mut t, &[row(100, 9)], "b.exe");
        let diff = taken(&mut t);
        assert_eq!(diff.gone, [(100, 1)]);
        assert_eq!(diff.passports[0].sequence_number, 9);
        assert_eq!(diff.passports[0].display_name, "", "nothing of the old process carries over");
    }

    #[test]
    fn the_same_snapshot_again_sends_nothing() {
        let mut t = table(&[row(100, 1)], "a.exe");
        assert!(sync(&mut t, &[row(100, 1)], "a.exe").is_empty());
        let diff = taken(&mut t);
        assert!(diff.gone.is_empty() && diff.passports.is_empty() && diff.states.is_empty());
    }

    #[test]
    fn only_a_state_that_changed_is_sent() {
        let mut t = table(&[row(100, 1), row(200, 2)], "a.exe");
        let state = |pid, sequence_number, suspended| ProcessState {
            pid,
            sequence_number,
            suspended: Some(suspended),
            ..Default::default()
        };
        t.observe(state(100, 1, true));
        t.observe(state(200, 2, false));
        taken(&mut t);
        t.observe(state(100, 1, true));
        t.observe(state(200, 2, true));
        assert_eq!(pids(&taken(&mut t)), (vec![], vec![200]));
    }

    #[test]
    fn a_state_of_an_earlier_process_on_the_same_pid_is_ignored() {
        let mut t = table(&[row(100, 2)], "a.exe");
        t.observe(ProcessState {
            pid: 100,
            sequence_number: 1,
            suspended: Some(true),
            ..Default::default()
        });
        assert!(taken(&mut t).states.is_empty());
    }

    #[test]
    fn a_process_joins_with_everything_its_handle_and_token_tell() {
        let mut t = ProcessTable::new();
        t.reconcile(&[row(100, 1)], |_| Sighted {
            image_name: "a.exe".into(),
            read: ProcessRead {
                image_path: r"C:\a.exe".into(),
                command_line: vec!["a.exe".into(), "-x".into()],
                passport: Passport {
                    user: r"HOST\me".into(),
                    architecture: Architecture::X64,
                    elevated: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }, |_| {});
        let entry = t.get(100).unwrap();
        assert_eq!(*entry.command_line, ["a.exe", "-x"]);
        assert_eq!(entry.user, r"HOST\me");
        assert_eq!((entry.architecture, entry.elevated), (Architecture::X64, Some(true)));
    }

    #[test]
    fn an_image_is_asked_for_once_whoever_runs_it() {
        let mut t = ProcessTable::new();
        let first = sync(&mut t, &[row(100, 1), row(200, 2)], "a.exe");
        assert_eq!(paths(&first), ["a.exe"]);
        let later = sync(&mut t, &[row(100, 1), row(200, 2), row(300, 3)], "a.exe");
        assert!(later.is_empty(), "still pending");
        assert_eq!(t.pending().collect::<Vec<_>>(), ["a.exe"]);
    }

    #[test]
    fn a_verdict_sends_the_passports_of_every_process_of_its_image() {
        let mut t = table(&[row(100, 1), row(200, 2)], "a.exe");
        t.judge(verdict("a.exe", "App"));
        let diff = taken(&mut t);
        assert_eq!(pids(&diff), (vec![100, 200], vec![]));
        assert!(diff.passports.iter().all(|p| p.display_name == "App" && p.publisher == "Contoso"));
        assert_eq!(t.pending().count(), 0);

        t.judge(verdict("a.exe", "App"));
        assert!(taken(&mut t).passports.is_empty(), "the same verdict again changes nothing");
    }

    #[test]
    fn a_process_of_a_judged_image_joins_named() {
        let mut t = table(&[row(100, 1)], "a.exe");
        t.judge(verdict("a.exe", "App"));
        let requests = sync(&mut t, &[row(100, 1), row(200, 2)], "a.exe");
        assert!(requests.is_empty());
        assert_eq!(t.get(200).unwrap().display_name, "App");
    }

    #[test]
    fn a_kernel_process_stays_a_windows_process_whatever_its_image_says() {
        let mut t = ProcessTable::new();
        t.reconcile(&[row(4, 1)], |_| Sighted {
            is_kernel_process: true,
            read: ProcessRead {
                image_path: "ntoskrnl.exe".into(),
                ..Default::default()
            },
            ..Default::default()
        }, |_| {});
        t.judge(verdict("ntoskrnl.exe", "Kernel"));
        assert!(t.get(4).unwrap().is_windows_process);
    }

    #[test]
    fn an_image_nobody_runs_any_more_is_forgotten_and_asked_for_again() {
        let mut t = table(&[row(100, 1)], "a.exe");
        sync(&mut t, &[], "a.exe");
        t.judge(verdict("a.exe", "App"));
        let again = sync(&mut t, &[row(200, 2)], "a.exe");
        assert_eq!(paths(&again), ["a.exe"]);
        assert_eq!(t.get(200).unwrap().display_name, "", "the late verdict was dropped");
    }

    #[test]
    fn an_image_is_kept_while_any_process_runs_it() {
        let mut t = table(&[row(100, 1), row(200, 2)], "a.exe");
        t.judge(verdict("a.exe", "App"));
        sync(&mut t, &[row(200, 2)], "a.exe");
        assert!(sync(&mut t, &[row(200, 2), row(300, 3)], "a.exe").is_empty());
        assert_eq!(t.get(300).unwrap().display_name, "App");

        sync(&mut t, &[row(200, 9)], "b.exe");
        assert_eq!(paths(&sync(&mut t, &[row(200, 9), row(400, 4)], "a.exe")), ["a.exe"], "a pid reused by another image lets go of the first");
    }

    #[test]
    fn a_process_without_an_image_path_asks_for_nothing() {
        let mut t = ProcessTable::new();
        assert!(sync(&mut t, &[row(100, 1)], "").is_empty());
    }
}
