use std::cell::Cell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::c_void;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};
use futures::Stream;
use futures::channel::mpsc;
use windows::Win32::{
    CloseHandle, CreateEventW, ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, ERROR_SUCCESS, HANDLE,
    INFINITE, NotifyServiceStatusChangeW, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_CONTINUE_PENDING,
    SERVICE_NOTIFY_DELETE_PENDING, SERVICE_NOTIFY_PAUSE_PENDING, SERVICE_NOTIFY_PAUSED,
    SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE,
    SERVICE_NOTIFY_STOP_PENDING, SERVICE_NOTIFY_STOPPED, SERVICE_QUERY_STATUS, SetEvent, SleepEx,
    WaitForSingleObjectEx,
};
use windows::core::PCWSTR;

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

enum Request {
    Watch {
        name: String,
        id: u64,
        tx: mpsc::UnboundedSender<ServiceStatus>,
    },
    Hold {
        name: String,
        id: u64,
        until: Instant,
    },
    Release {
        name: String,
        id: u64,
    },
}

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
    requests: Sender<Request>,
    wake: Event,
    stop: AtomicBool,
    next_id: AtomicU64,
}

/// Follows the services someone asks about, as the SCM reports their
/// changes, and hands every change to `publish`. Stops when dropped.
pub struct Watcher {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

/// Asks the watcher to follow a service; cheap to clone.
#[derive(Clone)]
pub struct Watching(Arc<Shared>);

impl Watcher {
    /// `publish` gets each followed service's status as it changes, and None once it is no longer followed.
    pub fn start(
        scm: Scm,
        publish: impl FnMut(&str, Option<&ServiceStatus>) + Send + 'static,
    ) -> std::io::Result<Self> {
        let (requests, queue) = crossbeam_channel::unbounded();
        let shared = Arc::new(Shared {
            requests,
            wake: Event::new()?,
            stop: AtomicBool::new(false),
            next_id: AtomicU64::new(0),
        });
        let thread = std::thread::Builder::new().name("service-watch".into()).spawn({
            let shared = shared.clone();
            move || run(scm, &shared, queue, publish)
        })?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    pub fn watching(&self) -> Watching {
        Watching(self.shared.clone())
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
        let (tx, rx) = mpsc::unbounded();
        let id = self.send(|id| Request::Watch {
            name: name.to_string(),
            id,
            tx,
        });
        ServiceWatch {
            rx,
            _release: self.release(name, id),
        }
    }

    /// Follows the service for at most `span`, or until the hold is dropped without [`Hold::keep`].
    pub fn hold(&self, name: &str, span: Duration) -> Hold {
        let until = Instant::now() + span;
        let id = self.send(|id| Request::Hold {
            name: name.to_string(),
            id,
            until,
        });
        Hold(self.release(name, id))
    }

    fn send(&self, request: impl FnOnce(u64) -> Request) -> u64 {
        let id = self.0.next_id.fetch_add(1, Ordering::Relaxed);
        if self.0.requests.send(request(id)).is_ok() {
            self.0.wake.set();
        }
        id
    }

    fn release(&self, name: &str, id: u64) -> Release {
        Release {
            shared: self.0.clone(),
            name: name.to_string(),
            id,
            armed: true,
        }
    }
}

struct Release {
    shared: Arc<Shared>,
    name: String,
    id: u64,
    armed: bool,
}

impl Drop for Release {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let request = Request::Release {
            name: std::mem::take(&mut self.name),
            id: self.id,
        };
        if self.shared.requests.send(request).is_ok() {
            self.shared.wake.set();
        }
    }
}

/// A service's status: the current one first, then every change. Ends
/// when the service is deleted, cannot be opened, or monitoring stops.
pub struct ServiceWatch {
    rx: mpsc::UnboundedReceiver<ServiceStatus>,
    _release: Release,
}

impl Stream for ServiceWatch {
    type Item = ServiceStatus;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<ServiceStatus>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }
}

/// Keeps a service followed while a command on it runs, and after it with [`keep`](Self::keep).
pub struct Hold(Release);

impl Hold {
    /// Leaves the service followed until the hold's span ends.
    pub fn keep(mut self) {
        self.0.armed = false;
    }
}

struct Watched {
    service: Option<Service>,
    notify: Box<SERVICE_NOTIFY_2W>,
    fired: Box<Cell<bool>>,
    last: Option<ServiceStatus>,
    watchers: HashMap<u64, mpsc::UnboundedSender<ServiceStatus>>,
    holds: HashMap<u64, Instant>,
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
            last: None,
            watchers: HashMap::new(),
            holds: HashMap::new(),
        };
        watched.reopen(scm, name);
        watched.service.is_some().then_some(watched)
    }

    fn reopen(&mut self, scm: &Scm, name: &str) {
        self.service = scm
            .connection()
            .ok()
            .and_then(|c| Service::open(c.handle(), name, SERVICE_QUERY_STATUS).ok());
        self.last = None;
        self.arm();
    }

    fn arm(&mut self) {
        let Some(service) = &self.service else {
            return;
        };
        let mask = (EVERY_STATE & !self.last.map_or(0, |s| bit(s.state))) | SERVICE_NOTIFY_DELETE_PENDING;
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

    fn notified(&mut self, scm: &Scm, name: &str, publish: &mut impl FnMut(&str, Option<&ServiceStatus>)) {
        let code = self.notify.dwNotificationStatus;
        if code == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING as u32 {
            self.reopen(scm, name);
            return;
        }
        if code != ERROR_SUCCESS as u32
            || self.notify.dwNotificationTriggered & SERVICE_NOTIFY_DELETE_PENDING as u32 != 0
        {
            self.service = None;
            return;
        }
        self.dispatch(name, status(&self.notify.ServiceStatus), publish);
        self.arm();
    }

    fn poll(&mut self, name: &str, publish: &mut impl FnMut(&str, Option<&ServiceStatus>)) {
        if let Some(status) = self.service.as_ref().and_then(Service::status) {
            self.dispatch(name, status, publish);
        }
    }

    fn dispatch(&mut self, name: &str, status: ServiceStatus, publish: &mut impl FnMut(&str, Option<&ServiceStatus>)) {
        if self.last == Some(status) {
            return;
        }
        self.last = Some(status);
        publish(name, Some(&status));
        self.watchers.retain(|_, tx| tx.unbounded_send(status).is_ok());
    }

    fn is_pending(&self) -> bool {
        self.last.is_some_and(|s| s.state.is_pending())
    }

    fn is_done(&self) -> bool {
        self.service.is_none() || (self.watchers.is_empty() && self.holds.is_empty())
    }
}

fn run(
    scm: Scm,
    shared: &Shared,
    queue: Receiver<Request>,
    mut publish: impl FnMut(&str, Option<&ServiceStatus>),
) {
    let mut watched: HashMap<String, Watched> = HashMap::new();
    let mut retired: Vec<Watched> = Vec::new();
    let mut next_poll = Instant::now();

    loop {
        let wait = timeout(&watched, next_poll);
        unsafe { WaitForSingleObjectEx(shared.wake.0, wait, true) };
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }

        for request in queue.try_iter() {
            apply(&scm, &mut watched, request);
        }

        for (name, w) in &mut watched {
            if w.fired.replace(false) {
                w.notified(&scm, name, &mut publish);
            }
        }

        let now = Instant::now();
        if now >= next_poll && watched.values().any(Watched::is_pending) {
            for (name, w) in &mut watched {
                if w.is_pending() {
                    w.poll(name, &mut publish);
                }
            }
            next_poll = now + POLL_WHILE_PENDING;
        }

        for w in watched.values_mut() {
            w.holds.retain(|_, until| *until > now);
        }

        let done: Vec<String> = watched
            .iter()
            .filter(|(_, w)| w.is_done())
            .map(|(name, _)| name.clone())
            .collect();
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

fn apply(scm: &Scm, watched: &mut HashMap<String, Watched>, request: Request) {
    match request {
        Request::Watch { name, id, tx } => {
            if let Some(w) = follow(scm, watched, name) {
                if let Some(status) = w.last {
                    let _ = tx.unbounded_send(status);
                }
                w.watchers.insert(id, tx);
            }
        }
        Request::Hold { name, id, until } => {
            if let Some(w) = follow(scm, watched, name) {
                w.holds.insert(id, until);
            }
        }
        Request::Release { name, id } => {
            if let Some(w) = watched.get_mut(&name) {
                w.watchers.remove(&id);
                w.holds.remove(&id);
            }
        }
    }
}

fn follow<'a>(scm: &Scm, watched: &'a mut HashMap<String, Watched>, name: String) -> Option<&'a mut Watched> {
    match watched.entry(name) {
        Entry::Occupied(entry) => Some(entry.into_mut()),
        Entry::Vacant(entry) => {
            let w = Watched::open(scm, entry.key())?;
            Some(entry.insert(w))
        }
    }
}

fn timeout(watched: &HashMap<String, Watched>, next_poll: Instant) -> u32 {
    if watched.values().any(|w| w.fired.get()) {
        return 0;
    }
    let polls = watched.values().any(Watched::is_pending).then_some(next_poll);
    let holds = watched.values().flat_map(|w| w.holds.values().copied());
    match polls.into_iter().chain(holds).min() {
        None => INFINITE,
        Some(at) => at.saturating_duration_since(Instant::now()).as_millis() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
