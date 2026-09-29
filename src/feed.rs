use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use crossbeam_channel::Sender;
use uniproc_agent_kit::Versioned;
use uniproc_windows_core::{Diff, Epoch, Health, Process, SessionHealth};

use crate::api::{
    MetricSpec, ProcessInfo, ProcessState, ProcessStates, Sample, ServiceState, ServiceStats,
    ServiceStatus, Snapshot,
};
use crate::sampler::{LocalSampler, Request, Subscriptions};
use crate::scm::ServiceEvent;

/// Everything the agent shows at one moment. Never changes once published.
#[derive(Clone, Debug)]
pub struct Published {
    pub snapshot: Snapshot,
    /// The last sample, its rows exactly the processes under its `passport_etag`.
    pub sample: Arc<Sample>,
    /// Events the core lost to a full channel since it started.
    pub dropped_by_sink: u64,
    pub sessions: Vec<SessionHealth>,
    /// Why the core could not read the process list last time; the sample
    /// and the lists stay as they were until it can.
    pub snapshot_error: Option<String>,
    /// When the core took its report; None before the first.
    pub reported_at: Option<Instant>,
}

/// What the agent shows now, and subscriptions to the samples it takes.
/// Readers take the latest whole; only the [`Painter`] publishes, and it
/// delivers each subscriber the samples it is due. Cheap to clone.
#[derive(Clone)]
pub struct Feed {
    latest: Arc<ArcSwap<Published>>,
    requests: Sender<Request>,
}

/// What the sources tell the picture.
pub(crate) enum Change {
    /// A tick of the core: what changed, and what it says about itself.
    Core(Diff, Health),
    Services(ServiceEvent),
}

/// Keeps the [`Picture`] on a thread of its own: applies what the sources
/// send, publishes to the feed whenever that tells something new, and hands
/// the core's emptied diffs back for its next tick. Stops when dropped.
pub(crate) struct Painter {
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

/// What the sources of the agent's picture tell it, kept up by the core's
/// diffs, the service scans and the followed services' statuses. The only
/// place that tags what the agent shows.
struct Picture {
    passports: BTreeMap<u32, ProcessInfo>,
    process_states: BTreeMap<u32, ProcessState>,
    taken: Arc<Sample>,
    health: Option<Health>,
    service_pids: HashSet<u32>,
    processes: Versioned<Arc<[ProcessInfo]>>,
    states: Versioned<ProcessStates>,
    sample: Arc<Sample>,
    services: Versioned<Arc<[ServiceStats]>>,
    followed: HashMap<String, (ServiceState, u32)>,
}

#[cfg(test)]
impl Published {
    /// Nothing listed yet, with `sample`.
    pub(crate) fn with(sample: Sample) -> Self {
        Self {
            sample: Arc::new(sample),
            ..Picture::new().publish()
        }
    }
}

impl Feed {
    pub fn latest(&self) -> Arc<Published> {
        self.latest.load_full()
    }

    /// Delivers what `spec` asks for until the sampler is dropped.
    pub fn subscribe(&self, spec: MetricSpec) -> LocalSampler {
        LocalSampler::subscribe(&self.requests, spec)
    }

    /// How often the core samples while nobody subscribes.
    pub fn set_idle(&self, idle: Duration) {
        let _ = self.requests.send(Request::Idle(idle));
    }
}

impl Painter {
    /// The painter, where the sources send their changes, and the feed it
    /// publishes to. `spare` gets the core's diffs back, emptied.
    pub fn start(mut subscriptions: Subscriptions, spare: Sender<Diff>) -> std::io::Result<(Self, Sender<Change>, Feed)> {
        let mut picture = Picture::new();
        let latest = Arc::new(ArcSwap::from_pointee(picture.publish()));
        let (changes, inbox) = crossbeam_channel::unbounded::<Change>();
        let (requests, asked) = crossbeam_channel::unbounded::<Request>();
        let (stop, stopped) = crossbeam_channel::bounded::<()>(0);
        let thread = std::thread::Builder::new().name("picture".into()).spawn({
            let latest = latest.clone();
            move || {
                loop {
                    crossbeam_channel::select! {
                        recv(inbox) -> change => {
                            let Ok(change) = change else { break };
                            let mut news = picture.apply(change, &spare);
                            for change in inbox.try_iter() {
                                news |= picture.apply(change, &spare);
                            }
                            if news {
                                let published = Arc::new(picture.publish());
                                latest.store(published.clone());
                                subscriptions.deliver(&published);
                            }
                        }
                        recv(asked) -> request => {
                            let Ok(request) = request else { break };
                            subscriptions.handle(request, &latest.load_full());
                        }
                        recv(stopped) -> _ => break,
                    }
                }
            }
        })?;
        let feed = Feed { latest, requests };
        Ok((
            Self {
                stop: Some(stop),
                thread: Some(thread),
            },
            changes,
            feed,
        ))
    }
}

impl Drop for Painter {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Picture {
    fn new() -> Self {
        let epoch = Epoch::new();
        Self {
            passports: BTreeMap::new(),
            process_states: BTreeMap::new(),
            taken: Arc::default(),
            health: None,
            service_pids: HashSet::new(),
            processes: Versioned::new(epoch, Arc::from([])),
            states: Versioned::new(epoch, ProcessStates::default()),
            sample: Arc::default(),
            services: Versioned::new(epoch, Arc::from([])),
            followed: HashMap::new(),
        }
    }

    /// Applies one change; true when it tells something new.
    fn apply(&mut self, change: Change, spare: &Sender<Diff>) -> bool {
        match change {
            Change::Core(mut diff, health) => {
                let news = self.update(&mut diff, health);
                let _ = spare.send(diff);
                news
            }
            Change::Services(ServiceEvent::Scan(services)) => self.services(services),
            Change::Services(ServiceEvent::Status(name, status)) => self.service_status(&name, status.as_ref()),
        }
    }

    /// Leaves `diff` empty, its buffers kept.
    fn update(&mut self, diff: &mut Diff, health: Health) -> bool {
        let mut listed = false;
        let restated = !diff.states.is_empty() || diff.sample.is_some();
        let news = self.health.as_ref().is_none_or(|last| news(last, &health));
        for (pid, sequence_number) in diff.gone.drain(..) {
            if self.passports.get(&pid).is_some_and(|p| p.sequence_number == sequence_number) {
                self.passports.remove(&pid);
                self.process_states.remove(&pid);
                listed = true;
            }
        }
        for passport in diff.passports.drain(..) {
            let is_service = self.service_pids.contains(&passport.pid);
            let process = info(passport, is_service);
            if self.passports.get(&process.pid) != Some(&process) {
                self.passports.insert(process.pid, process);
                listed = true;
            }
        }
        for state in diff.states.drain(..) {
            self.process_states.insert(state.pid, state);
        }
        if let Some(sample) = diff.sample.take() {
            self.taken = sample;
        }
        self.health = Some(health);
        if listed {
            self.list_processes();
        } else if restated {
            self.stamp();
        }
        listed || restated || news
    }

    fn stamp(&mut self) {
        let passport_etag = self.processes.get().etag;
        self.sample = Arc::new(Sample {
            passport_etag,
            ..(*self.taken).clone()
        });
        self.states.set(ProcessStates {
            passport_etag,
            states: self.process_states.values().copied().collect(),
        });
    }

    fn service_status(&mut self, name: &str, status: Option<&ServiceStatus>) -> bool {
        let Some(status) = status else {
            self.followed.remove(name);
            return false;
        };
        self.followed.insert(name.to_string(), (status.state, status.pid));
        self.services(self.services.get().value.to_vec())
    }

    fn services(&mut self, mut services: Vec<ServiceStats>) -> bool {
        for service in &mut services {
            if let Some(&(state, pid)) = self.followed.get(&service.name) {
                service.state = state;
                service.pid = pid;
            }
        }
        let moved = self.services.set(services.into());
        let pids: HashSet<u32> = self
            .services
            .get()
            .value
            .iter()
            .map(|s| s.pid)
            .filter(|&pid| pid != 0)
            .collect();
        if pids != self.service_pids {
            for pid in pids.symmetric_difference(&self.service_pids) {
                if let Some(process) = self.passports.get_mut(pid) {
                    process.is_service = pids.contains(pid);
                }
            }
            self.service_pids = pids;
            self.list_processes();
            return true;
        }
        moved
    }

    #[tracing::instrument(name = "list processes", level = "debug", skip_all)]
    fn list_processes(&mut self) {
        self.processes.replace(self.passports.values().cloned().collect());
        self.stamp();
    }

    fn publish(&self) -> Published {
        let health = self.health.as_ref();
        Published {
            snapshot: Snapshot {
                services: self.services.get().clone(),
                processes: self.processes.get().clone(),
                states: self.states.get().clone(),
            },
            sample: self.sample.clone(),
            dropped_by_sink: health.map_or(0, |h| h.dropped_by_sink),
            sessions: health.map_or_else(Vec::new, |h| h.sessions.clone()),
            snapshot_error: health.and_then(|h| h.snapshot_error.clone()),
            reported_at: health.map(|h| h.taken_at),
        }
    }
}

/// Whether `now` tells something `last` did not: a loss, a session that
/// stopped or came back, a snapshot that failed or reads again. Buffer
/// counters that move with every event are not news.
fn news(last: &Health, now: &Health) -> bool {
    last.dropped_by_sink != now.dropped_by_sink
        || last.snapshot_error != now.snapshot_error
        || !last.sessions.iter().map(losses).eq(now.sessions.iter().map(losses))
}

fn losses(s: &SessionHealth) -> (&str, bool, bool, u32, u32, u32) {
    (s.name.as_str(), s.running, s.pumping, s.events_lost, s.realtime_buffers_lost, s.log_buffers_lost)
}

fn info(p: Process, is_service: bool) -> ProcessInfo {
    ProcessInfo {
        pid: p.pid,
        parent_pid: p.parent_pid,
        session_id: p.session_id,
        name: p.name,
        cmdline: p.cmdline,
        package_full_name: p.package_full_name,
        package_relative_app_id: p.package_relative_app_id,
        is_service,
        is_kernel_process: p.is_kernel_process,
        is_windows_process: p.is_windows_process,
        signature: p.signature,
        image_path: p.image_path,
        display_name: p.display_name,
        console_host_pid: p.console_host_pid,
        start_time: p.start_time,
        sequence_number: p.sequence_number,
        user: p.user,
        architecture: p.architecture,
        elevated: p.elevated,
        uac_virtualization: p.uac_virtualization,
        isolation: p.isolation,
        dpi_awareness: p.dpi_awareness,
        mitigations: p.mitigations,
        publisher: p.publisher,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use uniproc_windows_core::Tagged;

    fn passport(pid: u32) -> Process {
        Process {
            pid,
            sequence_number: pid as u64 + 1000,
            ..Default::default()
        }
    }

    fn state(pid: u32) -> ProcessState {
        ProcessState {
            pid,
            sequence_number: pid as u64 + 1000,
            ..Default::default()
        }
    }

    fn sample(snapshot: u64, pids: &[u32]) -> Arc<Sample> {
        Arc::new(Sample {
            snapshot,
            pids: pids.into(),
            ..Default::default()
        })
    }

    fn health(snapshot_error: Option<&str>) -> Health {
        Health {
            dropped_by_sink: 0,
            sessions: Vec::new(),
            snapshot_error: snapshot_error.map(str::to_string),
            taken_at: Instant::now(),
        }
    }

    struct Painted {
        picture: RefCell<Picture>,
        latest: RefCell<Arc<Published>>,
        published: Cell<u64>,
    }

    impl Painted {
        fn new() -> Self {
            let picture = Picture::new();
            let latest = Arc::new(picture.publish());
            Self {
                picture: RefCell::new(picture),
                latest: RefCell::new(latest),
                published: Cell::new(0),
            }
        }

        fn update(&self, diff: &mut Diff, health: Health) {
            let news = self.picture.borrow_mut().update(diff, health);
            self.store(news);
        }

        fn store(&self, news: bool) {
            if news {
                *self.latest.borrow_mut() = Arc::new(self.picture.borrow().publish());
                self.published.set(self.published.get() + 1);
            }
        }

        fn services(&self, services: Vec<ServiceStats>) {
            self.change(Change::Services(ServiceEvent::Scan(services)));
        }

        fn service_status(&self, name: &str, status: Option<&ServiceStatus>) {
            self.change(Change::Services(ServiceEvent::Status(name.to_string(), status.copied())));
        }

        fn change(&self, change: Change) {
            let (spare, _) = crossbeam_channel::unbounded();
            let news = self.picture.borrow_mut().apply(change, &spare);
            self.store(news);
        }

        fn latest(&self) -> Arc<Published> {
            self.latest.borrow().clone()
        }

        fn generation(&self) -> u64 {
            self.published.get()
        }
    }

    fn apply(feed: &Painted, mut diff: Diff) {
        feed.update(&mut diff, health(None));
    }

    fn joined(feed: &Painted, pids: &[u32]) {
        apply(
            feed,
            Diff {
                passports: pids.iter().map(|&pid| passport(pid)).collect(),
                states: pids.iter().map(|&pid| state(pid)).collect(),
                sample: Some(sample(1, pids)),
                ..Default::default()
            },
        );
    }

    fn service(name: &str, pid: u32) -> ServiceStats {
        ServiceStats {
            name: name.to_string(),
            pid,
            ..Default::default()
        }
    }

    fn processes(feed: &Painted) -> Tagged<Arc<[ProcessInfo]>> {
        feed.latest().snapshot.processes.clone()
    }

    #[test]
    fn a_process_a_service_runs_in_is_a_service() {
        let feed = Painted::new();
        joined(&feed, &[10, 20]);
        feed.services(vec![service("a", 10)]);
        let listed = processes(&feed);
        assert!(listed.value.iter().find(|p| p.pid == 10).unwrap().is_service);
        assert!(!listed.value.iter().find(|p| p.pid == 20).unwrap().is_service);
    }

    #[test]
    fn an_applied_diff_is_left_empty_with_its_buffers() {
        let feed = Painted::new();
        let mut diff = Diff {
            passports: vec![passport(10), passport(20)],
            states: vec![state(10), state(20)],
            sample: Some(sample(1, &[10, 20])),
            ..Default::default()
        };
        feed.update(&mut diff, health(None));
        assert!(diff.passports.is_empty() && diff.states.is_empty() && diff.sample.is_none());
        assert!(diff.passports.capacity() >= 2 && diff.states.capacity() >= 2);
        assert_eq!(processes(&feed).value.len(), 2);
    }

    #[test]
    fn a_tick_with_nothing_new_publishes_nothing() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let seen = feed.generation();
        apply(&feed, Diff::default());
        assert_eq!(feed.generation(), seen);
    }

    #[test]
    fn a_snapshot_that_failed_is_news_without_a_diff() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let seen = feed.generation();
        feed.update(&mut Diff::default(), health(Some("no list")));
        assert!(feed.generation() > seen);
        assert_eq!(feed.latest().snapshot_error.as_deref(), Some("no list"));
        assert_eq!(processes(&feed).value.len(), 1, "the picture stays as it was");
    }

    #[test]
    fn an_empty_diff_keeps_the_same_arc() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let first = processes(&feed);
        apply(&feed, Diff::default());
        let again = processes(&feed);
        assert_eq!(first.etag, again.etag);
        assert!(Arc::ptr_eq(&first.value, &again.value));
    }

    #[test]
    fn the_same_passport_again_keeps_the_tag() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let first = processes(&feed).etag;
        apply(&feed, Diff { passports: vec![passport(10)], ..Default::default() });
        assert_eq!(processes(&feed).etag, first);
    }

    #[test]
    fn a_process_joining_moves_the_tag() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let first = processes(&feed);
        apply(
            &feed,
            Diff {
                passports: vec![passport(20)],
                states: vec![state(20)],
                sample: Some(sample(2, &[10, 20])),
                ..Default::default()
            },
        );
        let next = processes(&feed);
        assert_ne!(first.etag, next.etag);
        assert_eq!(next.value.iter().map(|p| p.pid).collect::<Vec<_>>(), [10, 20]);
        assert_eq!(feed.latest().snapshot.states.value.states.len(), 2);
    }

    #[test]
    fn a_process_leaving_takes_its_state_along() {
        let feed = Painted::new();
        joined(&feed, &[10, 20]);
        apply(
            &feed,
            Diff {
                gone: vec![(20, 1020)],
                sample: Some(sample(2, &[10])),
                ..Default::default()
            },
        );
        let latest = feed.latest();
        assert_eq!(latest.snapshot.processes.value.iter().map(|p| p.pid).collect::<Vec<_>>(), [10]);
        assert_eq!(latest.snapshot.states.value.states.iter().map(|s| s.pid).collect::<Vec<_>>(), [10]);
    }

    #[test]
    fn a_process_that_left_under_a_reused_pid_leaves_the_new_one_listed() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let listed = processes(&feed).etag;
        apply(&feed, Diff { gone: vec![(10, 7)], ..Default::default() });
        assert_eq!(processes(&feed).value.len(), 1);
        assert_eq!(processes(&feed).etag, listed);
    }

    #[test]
    fn a_service_changing_pid_moves_the_processes_tag_too() {
        let feed = Painted::new();
        joined(&feed, &[10, 20]);
        feed.services(vec![service("a", 10)]);
        let (listed, services) = (processes(&feed).etag, feed.latest().snapshot.services.etag);

        feed.services(vec![service("a", 20)]);
        assert_ne!(feed.latest().snapshot.services.etag, services);
        assert_ne!(processes(&feed).etag, listed, "is_service comes from the inventory");
    }

    #[test]
    fn a_description_change_leaves_the_processes_tag() {
        let feed = Painted::new();
        joined(&feed, &[10]);
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
        let feed = Painted::new();
        joined(&feed, &[10]);
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

    fn listed(feed: &Painted, name: &str) -> (ServiceState, u32) {
        let latest = feed.latest();
        let service = latest.snapshot.services.value.iter().find(|s| s.name == name).unwrap();
        (service.state, service.pid)
    }

    #[test]
    fn a_followed_change_shows_before_the_next_scan() {
        let feed = Painted::new();
        joined(&feed, &[10]);
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
        let feed = Painted::new();
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
    fn a_sample_carries_the_tag_of_the_list_it_was_taken_against() {
        let feed = Painted::new();
        joined(&feed, &[10, 20]);
        let latest = feed.latest();
        assert_eq!(latest.sample.passport_etag, latest.snapshot.processes.etag);
        assert_eq!(latest.snapshot.states.value.passport_etag, latest.snapshot.processes.etag);
        assert_eq!(latest.snapshot.states.value.states.len(), 2);
    }

    #[test]
    fn a_passport_change_without_a_sample_restamps_the_same_rows() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let sampled_against = feed.latest().sample.passport_etag;

        let judged = Process {
            display_name: "Ten".into(),
            ..passport(10)
        };
        apply(&feed, Diff { passports: vec![judged], ..Default::default() });
        let latest = feed.latest();
        assert_ne!(latest.snapshot.processes.etag, sampled_against, "the passport moved");
        assert_eq!(latest.sample.snapshot, 1, "no new sample");
        assert_eq!(latest.sample.passport_etag, latest.snapshot.processes.etag);
        assert_eq!(latest.snapshot.states.value.passport_etag, latest.snapshot.processes.etag);
    }

    #[test]
    fn a_service_moving_the_list_restamps_the_states_and_the_sample() {
        let feed = Painted::new();
        joined(&feed, &[10, 20]);
        feed.services(vec![service("a", 20)]);
        let latest = feed.latest();
        assert!(latest.snapshot.processes.value[1].is_service);
        assert_eq!(latest.sample.passport_etag, latest.snapshot.processes.etag);
        assert_eq!(latest.snapshot.states.value.passport_etag, latest.snapshot.processes.etag);
    }

    #[test]
    fn states_that_did_not_change_keep_their_tag() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let states = feed.latest().snapshot.states.etag;
        apply(&feed, Diff { sample: Some(sample(2, &[10])), ..Default::default() });
        let latest = feed.latest();
        assert_eq!(latest.sample.snapshot, 2);
        assert_eq!(latest.snapshot.states.etag, states);
    }

    #[test]
    fn a_changed_state_moves_the_states_tag() {
        let feed = Painted::new();
        joined(&feed, &[10]);
        let states = feed.latest().snapshot.states.etag;
        let suspended = ProcessState {
            suspended: Some(true),
            ..state(10)
        };
        apply(
            &feed,
            Diff {
                states: vec![suspended],
                sample: Some(sample(2, &[10])),
                ..Default::default()
            },
        );
        let latest = feed.latest();
        assert_ne!(latest.snapshot.states.etag, states);
        assert_eq!(latest.snapshot.states.value.states[0].suspended, Some(true));
    }

    #[test]
    fn the_painter_delivers_what_the_sources_send_and_hands_the_diff_back() {
        let wanted = MetricSpec {
            interval: Duration::from_secs(1),
            processes: [uniproc_windows_core::ProcessMetric::Handles].into_iter().collect(),
            machine: crate::api::MachineMetrics::empty(),
        };
        let (woke, wakes) = crossbeam_channel::unbounded();
        let subscriptions = Subscriptions::new(Duration::from_secs(2), move || {
            let _ = woke.send(());
        });
        let demand = subscriptions.demand();
        let (spare, spares) = crossbeam_channel::unbounded();
        let (painter, changes, feed) = Painter::start(subscriptions, spare).unwrap();

        let sampler = feed.subscribe(wanted);
        wakes.recv_timeout(Duration::from_secs(5)).expect("the core is woken");
        assert_eq!(*demand.get(), [wanted]);

        let diff = Diff {
            passports: vec![passport(10)],
            states: vec![state(10)],
            sample: Some(Arc::new(Sample {
                snapshot: 1,
                pids: [10].as_slice().into(),
                wanted,
                ..Default::default()
            })),
            ..Default::default()
        };
        changes.send(Change::Core(diff, health(None))).unwrap();
        let back = spares.recv_timeout(Duration::from_secs(5)).expect("the diff comes back");
        assert!(back.passports.is_empty() && back.passports.capacity() >= 1);
        let delivered = futures::executor::block_on(sampler.sample(0));
        assert_eq!(delivered.snapshot, 1);
        assert_eq!(feed.latest().snapshot.processes.value.len(), 1);

        drop(sampler);
        wakes.recv_timeout(Duration::from_secs(5)).expect("the core is woken");
        assert_eq!(*demand.get(), [MetricSpec::idle(Duration::from_secs(2))]);

        drop(painter);
        assert!(changes.send(Change::Services(ServiceEvent::Scan(Vec::new()))).is_err(), "the painter is gone");
    }
}
