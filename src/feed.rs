use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use uniproc_windows_core::{
    Epoch, MachineStats, Process, Report, Samples, SessionHealth, Tagged,
};

use crate::api::{ProcessInfo, ServiceState, ServiceStats, ServiceStatus, Snapshot};

/// Everything the agent shows at one moment. Never changes once published.
#[derive(Clone, Debug)]
pub struct Published {
    pub snapshot: Snapshot,
    /// Profile samples the core folded last time.
    pub samples: Samples,
    /// Events the core lost to a full channel since it started.
    pub dropped_by_sink: u64,
    pub sessions: Vec<SessionHealth>,
    /// When the core took its report; None before the first.
    pub reported_at: Option<Instant>,
}

/// The core's latest report joined with the latest service inventory,
/// joined again whenever either moves. Readers take the latest whole.
pub struct Feed {
    join: Mutex<Join>,
    latest: Mutex<Arc<Published>>,
}

struct Join {
    epoch: Epoch,
    report: Option<Arc<Report>>,
    service_pids: HashSet<u32>,
    processes_generation: u32,
    processes: Tagged<Arc<[ProcessInfo]>>,
    services_generation: u32,
    services: Tagged<Arc<[ServiceStats]>>,
    followed: HashMap<String, (ServiceState, u32)>,
}

impl Feed {
    pub fn new() -> Self {
        let join = Join::new();
        let latest = Arc::new(join.publish());
        Self {
            join: Mutex::new(join),
            latest: Mutex::new(latest),
        }
    }

    pub fn latest(&self) -> Arc<Published> {
        self.latest.lock().clone()
    }

    pub fn report(&self, report: Arc<Report>) {
        let mut join = self.join.lock();
        join.report(report);
        *self.latest.lock() = Arc::new(join.publish());
    }

    pub fn services(&self, services: Vec<ServiceStats>) {
        let mut join = self.join.lock();
        join.services(services);
        *self.latest.lock() = Arc::new(join.publish());
    }

    /// A followed service's status as it changes; it wins over an inventory
    /// scan taken before the change. None: no longer followed, scans rule again.
    pub fn service_status(&self, name: &str, status: Option<&ServiceStatus>) {
        let mut join = self.join.lock();
        join.service_status(name, status);
        *self.latest.lock() = Arc::new(join.publish());
    }
}

impl Join {
    fn new() -> Self {
        let epoch = Epoch::new();
        Self {
            epoch,
            report: None,
            service_pids: HashSet::new(),
            processes_generation: 0,
            processes: Tagged {
                etag: epoch.tag(0),
                value: Arc::from([]),
            },
            services_generation: 0,
            services: Tagged {
                etag: epoch.tag(0),
                value: Arc::from([]),
            },
            followed: HashMap::new(),
        }
    }

    fn report(&mut self, report: Arc<Report>) {
        let moved = self
            .report
            .as_ref()
            .is_none_or(|held| held.processes.etag != report.processes.etag);
        self.report = Some(report);
        if moved {
            self.list_processes();
        }
    }

    fn service_status(&mut self, name: &str, status: Option<&ServiceStatus>) {
        let Some(status) = status else {
            self.followed.remove(name);
            return;
        };
        self.followed.insert(name.to_string(), (status.state, status.pid));
        self.services(self.services.value.to_vec());
    }

    fn services(&mut self, mut services: Vec<ServiceStats>) {
        for service in &mut services {
            if let Some(&(state, pid)) = self.followed.get(&service.name) {
                service.state = state;
                service.pid = pid;
            }
        }
        if *self.services.value != *services {
            self.services_generation = self.services_generation.wrapping_add(1);
            self.services = Tagged {
                etag: self.epoch.tag(self.services_generation),
                value: services.into(),
            };
        }
        let pids: HashSet<u32> = self
            .services
            .value
            .iter()
            .map(|s| s.pid)
            .filter(|&pid| pid != 0)
            .collect();
        if pids != self.service_pids {
            self.service_pids = pids;
            self.list_processes();
        }
    }

    fn list_processes(&mut self) {
        let listed = self.report.as_ref().map_or(&[][..], |r| &r.processes.value[..]);
        let value = listed
            .iter()
            .map(|p| info(p, self.service_pids.contains(&p.pid)))
            .collect();
        self.processes_generation = self.processes_generation.wrapping_add(1);
        self.processes = Tagged {
            etag: self.epoch.tag(self.processes_generation),
            value,
        };
    }

    fn publish(&self) -> Published {
        let report = self.report.as_deref();
        Published {
            snapshot: Snapshot {
                machine: report.map_or_else(MachineStats::default, |r| r.machine.clone()),
                services: self.services.clone(),
                processes: self.processes.clone(),
                metrics: report.map_or_else(Vec::new, |r| r.metrics.clone()),
            },
            samples: report.map_or_else(Samples::default, |r| r.samples),
            dropped_by_sink: report.map_or(0, |r| r.dropped_by_sink),
            sessions: report.map_or_else(Vec::new, |r| r.sessions.clone()),
            reported_at: report.map(|r| r.taken_at),
        }
    }
}

fn info(p: &Process, is_service: bool) -> ProcessInfo {
    ProcessInfo {
        pid: p.pid,
        parent_pid: p.parent_pid,
        session_id: p.session_id,
        name: p.name.clone(),
        cmdline: p.cmdline.clone(),
        package_full_name: p.package_full_name.clone(),
        package_relative_app_id: p.package_relative_app_id.clone(),
        is_service,
        is_kernel_process: p.is_kernel_process,
        is_windows_process: p.is_windows_process,
        signature: p.signature,
        image_path: p.image_path.clone(),
        display_name: p.display_name.clone(),
        console_host_pid: p.console_host_pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniproc_windows_core::ProcessMetrics;

    fn report(etag: u64, pids: &[u32]) -> Arc<Report> {
        Arc::new(Report {
            machine: MachineStats::default(),
            processes: Tagged {
                etag,
                value: pids
                    .iter()
                    .map(|&pid| Process {
                        pid,
                        ..Default::default()
                    })
                    .collect(),
            },
            metrics: pids
                .iter()
                .map(|&pid| ProcessMetrics {
                    pid,
                    ..Default::default()
                })
                .collect(),
            samples: Samples::default(),
            dropped_by_sink: 0,
            sessions: Vec::new(),
            taken_at: Instant::now(),
        })
    }

    fn service(name: &str, pid: u32) -> ServiceStats {
        ServiceStats {
            name: name.to_string(),
            pid,
            ..Default::default()
        }
    }

    fn processes(feed: &Feed) -> Tagged<Arc<[ProcessInfo]>> {
        feed.latest().snapshot.processes.clone()
    }

    #[test]
    fn a_process_a_service_runs_in_is_a_service() {
        let feed = Feed::new();
        feed.report(report(1, &[10, 20]));
        feed.services(vec![service("a", 10)]);
        let listed = processes(&feed);
        assert!(listed.value.iter().find(|p| p.pid == 10).unwrap().is_service);
        assert!(!listed.value.iter().find(|p| p.pid == 20).unwrap().is_service);
    }

    #[test]
    fn a_report_with_the_same_list_keeps_the_same_arc() {
        let feed = Feed::new();
        feed.report(report(1, &[10]));
        let first = processes(&feed);
        feed.report(report(1, &[10]));
        let again = processes(&feed);
        assert_eq!(first.etag, again.etag);
        assert!(Arc::ptr_eq(&first.value, &again.value));
    }

    #[test]
    fn a_new_list_from_the_core_moves_the_tag() {
        let feed = Feed::new();
        feed.report(report(1, &[10]));
        let first = processes(&feed);
        feed.report(report(2, &[10, 20]));
        let next = processes(&feed);
        assert_ne!(first.etag, next.etag);
        assert_eq!(next.value.len(), 2);
    }

    #[test]
    fn a_service_changing_pid_moves_the_processes_tag_too() {
        let feed = Feed::new();
        feed.report(report(1, &[10, 20]));
        feed.services(vec![service("a", 10)]);
        let (listed, services) = (processes(&feed).etag, feed.latest().snapshot.services.etag);

        feed.services(vec![service("a", 20)]);
        assert_ne!(feed.latest().snapshot.services.etag, services);
        assert_ne!(processes(&feed).etag, listed, "is_service comes from the inventory");
    }

    #[test]
    fn a_description_change_leaves_the_processes_tag() {
        let feed = Feed::new();
        feed.report(report(1, &[10]));
        feed.services(vec![service("a", 10)]);
        let (listed, services) = (processes(&feed).etag, feed.latest().snapshot.services.etag);

        let mut described = service("a", 10);
        described.description = "now described".to_string();
        feed.services(vec![described]);
        assert_eq!(processes(&feed).etag, listed);
        assert_ne!(feed.latest().snapshot.services.etag, services);
    }

    #[test]
    fn the_same_inventory_again_keeps_both_tags() {
        let feed = Feed::new();
        feed.report(report(1, &[10]));
        feed.services(vec![service("a", 10)]);
        let before = feed.latest();

        feed.services(vec![service("a", 10)]);
        let after = feed.latest();
        assert_eq!(after.snapshot.processes.etag, before.snapshot.processes.etag);
        assert_eq!(after.snapshot.services.etag, before.snapshot.services.etag);
    }

    fn status(state: ServiceState, pid: u32) -> ServiceStatus {
        ServiceStatus {
            state,
            pid,
            ..Default::default()
        }
    }

    fn listed(feed: &Feed, name: &str) -> (ServiceState, u32) {
        let latest = feed.latest();
        let service = latest.snapshot.services.value.iter().find(|s| s.name == name).unwrap();
        (service.state, service.pid)
    }

    #[test]
    fn a_followed_change_shows_before_the_next_scan() {
        let feed = Feed::new();
        feed.report(report(1, &[10]));
        feed.services(vec![ServiceStats {
            state: ServiceState::Running,
            ..service("a", 10)
        }]);
        let before = feed.latest().snapshot.clone();

        feed.service_status("a", Some(&status(ServiceState::Stopped, 0)));
        assert_eq!(listed(&feed, "a"), (ServiceState::Stopped, 0));
        let after = feed.latest();
        assert_ne!(after.snapshot.services.etag, before.services.etag);
        assert_ne!(after.snapshot.processes.etag, before.processes.etag, "10 is no longer a service");
        assert!(!after.snapshot.processes.value[0].is_service);
    }

    #[test]
    fn a_scan_taken_before_the_change_does_not_undo_it() {
        let feed = Feed::new();
        let stale = vec![ServiceStats {
            state: ServiceState::Running,
            ..service("a", 10)
        }];
        feed.services(stale.clone());
        feed.service_status("a", Some(&status(ServiceState::StopPending, 10)));
        feed.services(stale.clone());
        assert_eq!(listed(&feed, "a"), (ServiceState::StopPending, 10));

        feed.service_status("a", None);
        feed.services(stale);
        assert_eq!(listed(&feed, "a"), (ServiceState::Running, 10), "unfollowed, scans rule again");
    }

    #[test]
    fn metrics_come_with_the_list_they_cover() {
        let feed = Feed::new();
        feed.report(report(1, &[10, 20, 30]));
        let latest = feed.latest();
        assert_eq!(latest.snapshot.metrics.len(), latest.snapshot.processes.value.len());
    }
}
