use std::sync::Arc;

use fxhash::FxHashMap;

use crate::model::{Architecture, DpiAwareness, Isolation, Mitigations, UacVirtualization};
use crate::snapshot::Row;
use crate::state::events::{ProcessEnriched, ProcessSignature};

/// What a process is when the snapshot first lists it; the enricher adds the rest.
#[derive(Clone, Debug, Default)]
pub struct Sighted {
    pub image_name: String,
    pub package_full_name: String,
    pub package_relative_app_id: String,
    pub is_kernel_process: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub sequence_number: u64,
    /// FILETIME.
    pub start_time: u64,
    pub image_name: String,
    pub image_path: String,
    /// Resolved by the enrichment pass; empty until then, and empty for
    /// anything whose name could not be resolved at all.
    pub display_name: String,
    pub command_line: Arc<[String]>,
    pub package_name: String,
    pub package_relative_app_id: String,

    pub signature: ProcessSignature,
    pub is_kernel_process: bool,
    pub is_windows_process: bool,
    pub console_host_pid: u32,

    pub user: String,
    pub architecture: Architecture,
    pub elevated: Option<bool>,
    pub uac_virtualization: UacVirtualization,
    pub isolation: Isolation,
    pub dpi_awareness: DpiAwareness,
    pub mitigations: Option<Mitigations>,
    pub publisher: String,
}

impl ProcessEntry {
    fn sighted(row: &Row, sighted: Sighted) -> Self {
        Self {
            pid: row.pid,
            parent_pid: row.parent_pid,
            session_id: row.session_id,
            sequence_number: row.sequence_number,
            start_time: row.create_time,
            image_name: sighted.image_name,
            package_name: sighted.package_full_name,
            package_relative_app_id: sighted.package_relative_app_id,
            is_kernel_process: sighted.is_kernel_process,
            is_windows_process: sighted.is_kernel_process,
            command_line: Arc::from([]),
            ..Default::default()
        }
    }
}

/// The processes the last snapshot listed, keyed by pid.
pub struct ProcessTable {
    processes: FxHashMap<u32, ProcessEntry>,
    passports: u32,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            processes: FxHashMap::default(),
            passports: 0,
        }
    }

    /// Moves whenever anything a process's passport (the protocol's
    /// ProcessInfo) is built from changes, or a process joins or leaves.
    pub fn passport_generation(&self) -> u32 {
        self.passports
    }

    fn passport_changed(&mut self) {
        self.passports = self.passports.wrapping_add(1);
    }

    /// Makes the table exactly the snapshot's processes: a pid whose sequence
    /// number moved is a new process. Returns the rows it added.
    pub fn reconcile<'a>(&mut self, rows: &'a [Row], mut sight: impl FnMut(&Row) -> Sighted) -> Vec<&'a Row> {
        let mut added = Vec::new();
        for row in rows {
            let known = self
                .processes
                .get(&row.pid)
                .is_some_and(|entry| entry.sequence_number == row.sequence_number);
            if !known {
                self.processes
                    .insert(row.pid, ProcessEntry::sighted(row, sight(row)));
                added.push(row);
            }
        }
        let listed: FxHashMap<u32, u64> = rows.iter().map(|r| (r.pid, r.sequence_number)).collect();
        let before = self.processes.len();
        self.processes
            .retain(|pid, entry| listed.get(pid) == Some(&entry.sequence_number));
        if !added.is_empty() || self.processes.len() != before {
            self.passport_changed();
        }
        added
    }

    pub fn enrich(&mut self, e: ProcessEnriched) {
        let Some(entry) = self.processes.get_mut(&e.pid) else {
            return;
        };
        if entry.sequence_number != e.sequence_number {
            return;
        }
        let p = &e.passport;
        let is_windows_process = entry.is_kernel_process || e.is_windows_process;
        let package_moved = !e.package_full_name.is_empty()
            && (entry.package_name != e.package_full_name
                || entry.package_relative_app_id != e.package_relative_app_id);
        let changed = (!e.command_line.is_empty() && *entry.command_line != e.command_line)
            || entry.image_path != e.image_path
            || entry.display_name != e.display_name
            || entry.signature != e.signature
            || entry.is_windows_process != is_windows_process
            || entry.console_host_pid != e.console_host_pid
            || package_moved
            || entry.publisher != e.publisher
            || entry.user != p.user
            || entry.architecture != p.architecture
            || entry.elevated != p.elevated
            || entry.uac_virtualization != p.uac_virtualization
            || entry.isolation != p.isolation
            || entry.dpi_awareness != p.dpi_awareness
            || entry.mitigations != p.mitigations;
        if !changed {
            return;
        }
        if !e.command_line.is_empty() {
            entry.command_line = e.command_line.into();
        }
        if package_moved {
            entry.package_name = e.package_full_name;
            entry.package_relative_app_id = e.package_relative_app_id;
        }
        entry.image_path = e.image_path;
        entry.display_name = e.display_name;
        entry.signature = e.signature;
        entry.is_windows_process = is_windows_process;
        entry.console_host_pid = e.console_host_pid;
        entry.publisher = e.publisher;
        entry.user = e.passport.user;
        entry.architecture = e.passport.architecture;
        entry.elevated = e.passport.elevated;
        entry.uac_virtualization = e.passport.uac_virtualization;
        entry.isolation = e.passport.isolation;
        entry.dpi_awareness = e.passport.dpi_awareness;
        entry.mitigations = e.passport.mitigations;
        self.passport_changed();
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.get(&pid)
    }

    pub fn entries(&self) -> impl Iterator<Item = &ProcessEntry> {
        self.processes.values()
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
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

    fn named(row: &Row) -> Sighted {
        Sighted {
            image_name: format!("p{}.exe", row.pid),
            ..Default::default()
        }
    }

    fn table(rows: &[Row]) -> ProcessTable {
        let mut t = ProcessTable::new();
        t.reconcile(rows, named);
        t
    }

    fn enriched(pid: u32, sequence_number: u64, display_name: &str) -> ProcessEnriched {
        ProcessEnriched {
            pid,
            sequence_number,
            display_name: display_name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_table_becomes_exactly_the_snapshot() {
        let mut t = table(&[row(100, 1), row(200, 2)]);
        let next = [row(200, 2), row(300, 3)];
        let added = t.reconcile(&next, named);
        assert_eq!(added.iter().map(|r| r.pid).collect::<Vec<_>>(), [300]);
        let mut pids: Vec<u32> = t.entries().map(|e| e.pid).collect();
        pids.sort();
        assert_eq!(pids, [200, 300]);
    }

    #[test]
    fn a_reused_pid_is_a_new_process() {
        let mut t = table(&[row(100, 1)]);
        t.enrich(enriched(100, 1, "Old"));
        let next = [row(100, 9)];
        let added = t.reconcile(&next, named);
        assert_eq!(added.len(), 1);
        let entry = t.get(100).unwrap();
        assert_eq!(entry.sequence_number, 9);
        assert_eq!(entry.display_name, "", "nothing of the old process carries over");
    }

    #[test]
    fn the_same_snapshot_again_moves_nothing() {
        let mut t = table(&[row(100, 1)]);
        let before = t.passport_generation();
        assert!(t.reconcile(&[row(100, 1)], named).is_empty());
        assert_eq!(t.passport_generation(), before);
    }

    #[test]
    fn a_process_leaving_moves_the_passports() {
        let mut t = table(&[row(100, 1), row(200, 2)]);
        let before = t.passport_generation();
        t.reconcile(&[row(100, 1)], named);
        assert_ne!(t.passport_generation(), before);
    }

    #[test]
    fn an_enrichment_moves_them_only_when_the_passport_changes() {
        let mut t = table(&[row(100, 1)]);
        t.enrich(enriched(100, 1, "Probe"));
        let named_once = t.passport_generation();

        t.enrich(enriched(100, 1, "Probe"));
        assert_eq!(t.passport_generation(), named_once, "nothing changed");

        t.enrich(enriched(100, 1, "Renamed"));
        assert_ne!(t.passport_generation(), named_once);
    }

    #[test]
    fn an_enrichment_for_an_earlier_process_on_the_same_pid_is_dropped() {
        let mut t = table(&[row(100, 2)]);
        let before = t.passport_generation();
        t.enrich(enriched(100, 1, "Ghost"));
        assert_eq!(t.passport_generation(), before);
        assert_eq!(t.get(100).unwrap().display_name, "");
    }

    #[test]
    fn the_passport_details_arrive_with_the_enrichment() {
        let mut t = table(&[row(100, 1)]);
        t.enrich(ProcessEnriched {
            publisher: "Contoso".into(),
            passport: Passport {
                user: r"HOST\me".into(),
                architecture: Architecture::X64,
                elevated: Some(true),
                ..Default::default()
            },
            ..enriched(100, 1, "A")
        });
        let entry = t.get(100).unwrap();
        assert_eq!((entry.user.as_str(), entry.publisher.as_str()), (r"HOST\me", "Contoso"));
        assert_eq!((entry.architecture, entry.elevated), (Architecture::X64, Some(true)));
    }
}
