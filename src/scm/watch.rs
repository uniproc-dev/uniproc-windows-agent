use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use uniproc_agent_kit::{Board, Following, Hold, Watch};
use crate::bindings::{
    CloseHandle, CreateEventW, ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, ERROR_SUCCESS, HANDLE,
    INFINITE, NotifyServiceStatusChangeW, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_CONTINUE_PENDING,
    SERVICE_NOTIFY_DELETE_PENDING, SERVICE_NOTIFY_PAUSE_PENDING, SERVICE_NOTIFY_PAUSED,
    SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE,
    SERVICE_NOTIFY_STOP_PENDING, SERVICE_NOTIFY_STOPPED, SERVICE_QUERY_STATUS, SetEvent, SleepEx,
    WaitForSingleObjectEx,
};
use windows_core::PCWSTR;

use crate::api::{ServiceState, ServiceStatus};
use crate::scm::{Scm, Service, status};

/// The SCM tells state changes, not progress; a pending service is asked this often.
const POLL_WHILE_PENDING: Duration = Duration::from_millis(250);

const EVERY_STATE: i32 = SERVICE_NOTIFY_STOPPED
    | SERVICE_NOTIFY_START_PENDING
    | SERVICE_NOTIFY_STOP_PENDING
    | SERVICE_NOTIFY_RUNNING
    | SERVICE_NOTIFY_CONTINUE_PENDING
    | SERVICE_NOTIFY_PAUSE_PENDING
    | SERVICE_NOTIFY_PAUSED;

fn bit(state: ServiceState) -> i32 {
    match state {
        ServiceState::Unknown => 0,
        ServiceState::Stopped => SERVICE_NOTIFY_STOPPED,
        ServiceState::StartPending => SERVICE_NOTIFY_START_PENDING,
        ServiceState::StopPending => SERVICE_NOTIFY_STOP_PENDING,
        ServiceState::Running => SERVICE_NOTIFY_RUNNING,
        ServiceState::ContinuePending => SERVICE_NOTIFY_CONTINUE_PENDING,
        ServiceState::PausePending => SERVICE_NOTIFY_PAUSE_PENDING,
        ServiceState::Paused => SERVICE_NOTIFY_PAUSED,
    }
}

/// A service's status: the current one first, then every change. Ends
/// when the service is deleted, cannot be opened, or monitoring stops.
pub type ServiceWatch = Watch<ServiceStatus>;

type Services = Board<String, ServiceStatus>;

struct Event(HANDLE);

unsafe impl Send for Event {}
unsafe impl Sync for Event {}

impl Event {
    fn new() -> std::io::Result<Self> {
        let handle = unsafe { CreateEventW(None, false, false, PCWSTR::null()) };
        if handle.0.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    fn set(&self) {
        let _ = unsafe { SetEvent(self.0) };
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct Shared {
    wake: Event,
    stop: AtomicBool,
}

/// Follows the services someone asks about, as the SCM reports their
/// changes, and hands every change to `publish`. Stops when dropped.
pub struct Watcher {
    shared: Arc<Shared>,
    following: Following<String, ServiceStatus>,
    thread: Option<JoinHandle<()>>,
}

/// Asks the watcher to follow a service; cheap to clone.
#[derive(Clone)]
pub struct Watching(Following<String, ServiceStatus>);

impl Watcher {
    /// `publish` gets each followed service's status as it changes, and None once it is no longer followed.
    pub fn start(
        scm: Scm,
        publish: impl FnMut(&str, Option<&ServiceStatus>) + Send + 'static,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            wake: Event::new()?,
            stop: AtomicBool::new(false),
        });
        let (following, services) = uniproc_agent_kit::board({
            let shared = shared.clone();
            move || shared.wake.set()
        });
        let thread = std::thread::Builder::new().name("service-watch".into()).spawn({
            let shared = shared.clone();
            move || run(scm, &shared, services, publish)
        })?;
        Ok(Self {
            shared,
            following,
            thread: Some(thread),
        })
    }

    pub fn watching(&self) -> Watching {
        Watching(self.following.clone())
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.wake.set();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Watching {
    /// The service's status now, then every change until the stream is dropped.
    pub fn watch(&self, name: &str) -> ServiceWatch {
        self.0.watch(name.to_string())
    }

    /// Follows the service for at most `span`, or until the hold is dropped without [`Hold::keep`].
    pub fn hold(&self, name: &str, span: Duration) -> Hold {
        self.0.hold(name.to_string(), span)
    }
}

struct Watched {
    service: Option<Service>,
    notify: Box<SERVICE_NOTIFY_2W>,
    fired: Box<Cell<bool>>,
}

unsafe extern "system" fn notified(parameter: *const c_void) {
    let notify = unsafe { &*(parameter as *const SERVICE_NOTIFY_2W) };
    let fired = unsafe { &*(notify.pContext as *const Cell<bool>) };
    fired.set(true);
}

impl Watched {
    fn open(scm: &Scm, name: &str) -> Option<Self> {
        let mut watched = Self {
            service: None,
            notify: Box::default(),
            fired: Box::new(Cell::new(false)),
        };
        watched.connect(scm, name);
        watched.service.is_some().then_some(watched)
    }

    fn connect(&mut self, scm: &Scm, name: &str) {
        self.service = scm
            .connection()
            .ok()
            .and_then(|c| Service::open(c.handle(), name, SERVICE_QUERY_STATUS).ok());
        self.arm(None);
    }

    fn arm(&mut self, last: Option<&ServiceStatus>) {
        let Some(service) = &self.service else {
            return;
        };
        let mask = (EVERY_STATE & !last.map_or(0, |s| bit(s.state))) | SERVICE_NOTIFY_DELETE_PENDING;
        *self.notify = SERVICE_NOTIFY_2W {
            dwVersion: SERVICE_NOTIFY_STATUS_CHANGE as u32,
            pfnNotifyCallback: Some(notified),
            pContext: &*self.fired as *const Cell<bool> as *mut c_void,
            ..Default::default()
        };
        let code = unsafe { NotifyServiceStatusChangeW(service.0, mask as u32, &*self.notify) };
        if code != ERROR_SUCCESS as u32 {
            self.service = None;
        }
    }

    fn notified(
        &mut self,
        scm: &Scm,
        name: &String,
        services: &mut Services,
        publish: &mut impl FnMut(&str, Option<&ServiceStatus>),
    ) {
        let code = self.notify.dwNotificationStatus;
        if code == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING as u32 {
            services.forget(name);
            self.connect(scm, name);
            return;
        }
        if code != ERROR_SUCCESS as u32
            || self.notify.dwNotificationTriggered & SERVICE_NOTIFY_DELETE_PENDING as u32 != 0
        {
            self.service = None;
            return;
        }
        dispatch(name, status(&self.notify.ServiceStatus), services, publish);
        self.arm(services.last(name));
    }

    fn poll(&mut self, name: &String, services: &mut Services, publish: &mut impl FnMut(&str, Option<&ServiceStatus>)) {
        if let Some(status) = self.service.as_ref().and_then(Service::status) {
            dispatch(name, status, services, publish);
        }
    }
}

fn dispatch(
    name: &String,
    status: ServiceStatus,
    services: &mut Services,
    publish: &mut impl FnMut(&str, Option<&ServiceStatus>),
) {
    if services.last(name) == Some(&status) {
        return;
    }
    publish(name, Some(&status));
    services.publish(name, status);
}

fn is_pending(services: &Services, name: &String) -> bool {
    services.last(name).is_some_and(|s| s.state.is_pending())
}

fn run(
    scm: Scm,
    shared: &Shared,
    mut services: Services,
    mut publish: impl FnMut(&str, Option<&ServiceStatus>),
) {
    let mut watched: HashMap<String, Watched> = HashMap::new();
    let mut retired: Vec<Watched> = Vec::new();
    let mut next_poll = Instant::now();

    loop {
        let wait = timeout(&watched, &services, next_poll);
        unsafe { WaitForSingleObjectEx(shared.wake.0, wait, true) };
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }

        services.take_requests(|name| match Watched::open(&scm, name) {
            Some(w) => {
                watched.insert(name.clone(), w);
                true
            }
            None => false,
        });

        for (name, w) in &mut watched {
            if w.fired.replace(false) {
                w.notified(&scm, name, &mut services, &mut publish);
            }
        }

        let now = Instant::now();
        if now >= next_poll && watched.keys().any(|name| is_pending(&services, name)) {
            for (name, w) in &mut watched {
                if is_pending(&services, name) {
                    w.poll(name, &mut services, &mut publish);
                }
            }
            next_poll = now + POLL_WHILE_PENDING;
        }

        let gone: Vec<String> = watched
            .iter()
            .filter(|(_, w)| w.service.is_none())
            .map(|(name, _)| name.clone())
            .collect();
        for name in &gone {
            services.end(name);
        }
        let done = gone.into_iter().chain(services.sweep(now));
        for name in done {
            if let Some(mut w) = watched.remove(&name) {
                w.service.take();
                publish(&name, None);
                retired.push(w);
            }
        }
        if !retired.is_empty() {
            unsafe { SleepEx(0, true) };
            retired.clear();
        }
    }

    for w in watched.values_mut() {
        w.service.take();
    }
    unsafe { SleepEx(0, true) };
}

fn timeout(watched: &HashMap<String, Watched>, services: &Services, next_poll: Instant) -> u32 {
    if watched.values().any(|w| w.fired.get()) {
        return 0;
    }
    let polls = watched
        .keys()
        .any(|name| is_pending(services, name))
        .then_some(next_poll);
    match polls.into_iter().chain(services.next_deadline()).min() {
        None => INFINITE,
        Some(at) => at.saturating_duration_since(Instant::now()).as_millis() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::Receiver;
    use futures::StreamExt;

    fn next(watch: &mut ServiceWatch) -> Option<ServiceStatus> {
        futures::executor::block_on(async {
            let timeout = futures_timer(Duration::from_secs(10));
            futures::pin_mut!(timeout);
            match futures::future::select(watch.next(), timeout).await {
                futures::future::Either::Left((status, _)) => status,
                futures::future::Either::Right(_) => panic!("no status within 10 s"),
            }
        })
    }

    fn futures_timer(after: Duration) -> impl std::future::Future<Output = ()> {
        let (tx, rx) = futures::channel::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(after);
            let _ = tx.send(());
        });
        async move {
            let _ = rx.await;
        }
    }

    fn watcher() -> (Watcher, Receiver<(String, Option<ServiceStatus>)>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let watcher = Watcher::start(Scm::new(), move |name, status| {
            let _ = tx.send((name.to_string(), status.copied()));
        })
        .unwrap();
        (watcher, rx)
    }

    #[test]
    fn a_watch_starts_with_the_current_status() {
        let (watcher, published) = watcher();
        let mut watch = watcher.watching().watch("EventLog");
        let status = next(&mut watch).expect("EventLog exists");
        assert_eq!(status.state, ServiceState::Running);
        assert_ne!(status.pid, 0);
        let (name, first) = published.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((name.as_str(), first), ("EventLog", Some(status)));
    }

    #[test]
    fn a_second_watch_on_the_same_service_gets_the_status_at_once() {
        let (watcher, _published) = watcher();
        let watching = watcher.watching();
        let mut first = watching.watch("EventLog");
        let status = next(&mut first).unwrap();
        let mut second = watching.watch("EventLog");
        assert_eq!(next(&mut second), Some(status));
    }

    #[test]
    fn a_service_that_does_not_exist_ends_the_stream() {
        let (watcher, _published) = watcher();
        let mut watch = watcher.watching().watch("Uniproc-No-Such-Service");
        assert_eq!(next(&mut watch), None);
    }

    #[test]
    fn a_dropped_watch_is_no_longer_followed() {
        let (watcher, published) = watcher();
        let mut watch = watcher.watching().watch("EventLog");
        next(&mut watch).unwrap();
        drop(watch);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut ended = false;
        while !ended && Instant::now() < deadline {
            if let Ok((_, status)) = published.recv_timeout(Duration::from_millis(200)) {
                ended = status.is_none();
            }
        }
        assert!(ended, "publish heard no end of following");
    }

    #[test]
    fn stopping_the_watcher_ends_every_watch() {
        let (watcher, _published) = watcher();
        let mut watch = watcher.watching().watch("EventLog");
        next(&mut watch).unwrap();
        drop(watcher);
        assert_eq!(next(&mut watch), None);
    }
}
