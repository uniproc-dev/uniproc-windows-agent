use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use anyhow::Result;
use tracing::error;
use windows::Win32::{EVENT_RECORD, ProcessTrace};
use windows::core::{GUID, w};

use crate::etw::consumer::{EventSink, TraceConsumer};
use crate::etw::session::{EtwSession, SessionMode};
use crate::etw::vars::{KERNEL_SESSION_NAME, SESSION_NAME_PREFIX};
use crate::sink::Sink;
use crate::state::events::StateChange;

#[cfg(test)]
fn manifest_session_name(guid: &GUID) -> String {
    manifest_session_name_in(SESSION_NAME_PREFIX, guid)
}

fn manifest_session_name_in(prefix: &str, guid: &GUID) -> String {
    format!("{prefix}{guid:?}").replace(['{', '}'], "")
}

fn qpc_ticks(d: std::time::Duration) -> i64 {
    let mut per_second = 0i64;
    let _ = unsafe { windows::Win32::QueryPerformanceFrequency(&mut per_second) };
    (d.as_secs_f64() * per_second as f64) as i64
}

type Handler = Box<dyn FnMut(&EVENT_RECORD, &[u8], &mut Vec<StateChange>) + Send>;

/// Folds a provider's events into one change, handed over at most once per
/// window instead of once per event.
pub trait Batch: Send {
    fn add(&mut self, record: &EVENT_RECORD, data: &[u8]);
    /// The accumulated change, leaving the batch empty; `None` when nothing
    /// was added since the last one.
    fn take(&mut self) -> Option<StateChange>;
}

struct BatchSlot {
    batch: Box<dyn Batch>,
    window: i64,
    since: Option<i64>,
}

#[derive(Clone, Copy)]
enum Target {
    Handler(usize),
    Batch(usize),
}

pub struct EnableFlags(pub u32);

impl From<i32> for EnableFlags {
    fn from(flags: i32) -> Self {
        Self(flags as u32)
    }
}

impl From<u32> for EnableFlags {
    fn from(flags: u32) -> Self {
        Self(flags)
    }
}

pub struct KernelRouterBuilder {
    flags: u32,
    manifest: Vec<GUID>,
    handlers: Vec<Handler>,
    batches: Vec<BatchSlot>,
    routes: Vec<(u128, Vec<Target>)>,
    prefix: String,
    kernel_session: String,
}

impl KernelRouterBuilder {
    pub fn on<F, I>(&mut self, providers: &'static [GUID], mut handler: F) -> &mut Self
    where
        F: FnMut(&EVENT_RECORD, &[u8]) -> I + Send + 'static,
        I: IntoIterator<Item = StateChange>,
    {
        let idx = self.handlers.len();
        self.handlers.push(Box::new(move |record, data, out| {
            out.extend(handler(record, data));
        }));
        self.route(providers, Target::Handler(idx));
        self
    }

    /// Routes `providers` into `batch`, handed over once `window` has passed
    /// since its first event. The deadline is checked on every event any
    /// session delivers, so a quiet provider's batch does not wait for its
    /// own next event.
    pub fn batched(
        &mut self,
        providers: &'static [GUID],
        window: std::time::Duration,
        batch: impl Batch + 'static,
    ) -> &mut Self {
        let idx = self.batches.len();
        self.batches.push(BatchSlot {
            batch: Box::new(batch),
            window: qpc_ticks(window),
            since: None,
        });
        self.route(providers, Target::Batch(idx));
        self
    }

    fn route(&mut self, providers: &'static [GUID], target: Target) {
        for guid in providers {
            let key = guid.to_u128();
            match self.routes.iter_mut().find(|(g, _)| *g == key) {
                Some((_, targets)) => targets.push(target),
                None => self.routes.push((key, vec![target])),
            }
        }
    }

    /// Legacy MOF providers: NT Kernel Logger session, EnableFlags.
    pub fn kernel_flags(&mut self, flags: impl Into<EnableFlags>) -> &mut Self {
        self.flags |= flags.into().0;
        self
    }

    pub fn session_namespace(&mut self, prefix: &str) -> &mut Self {
        self.prefix = prefix.to_string();
        self.kernel_session = format!("{prefix}Kernel");
        self
    }

    /// Manifest providers: own session per GUID, enabled via EnableTraceEx2.
    /// Events are matched by EventDescriptor.Id inside the handler.
    pub fn manifest(&mut self, provider: GUID) -> &mut Self {
        self.manifest.push(provider);
        self
    }

    /// Freezes the routes, brings the sessions up, opens the consumers and
    /// spawns a pump thread per session (ProcessTrace takes at most one
    /// real-time session; all pumps share one mutex-guarded RouterCore).
    pub fn start(self, sink: Sink) -> Result<KernelRouter> {
        let Self {
            flags,
            manifest,
            handlers,
            batches,
            routes,
            prefix,
            kernel_session,
        } = self;

        let mut core = Box::new(parking_lot::Mutex::new(RouterCore {
            routes,
            handlers,
            batches,
            sink,
            scratch: Vec::new(),
        }));
        let ptr: *mut parking_lot::Mutex<RouterCore> = &mut *core;

        let mut sessions = Vec::new();
        let mut consumers = Vec::new();

        if flags != 0 {
            crate::privileges::enable(w!("SeSystemProfilePrivilege"))?;
            let session = EtwSession::start(&kernel_session, flags, SessionMode::SystemLogger)?;
            // SAFETY: ptr points at `core`, which KernelRouter owns and drops
            // only after every pump thread has been joined; callbacks from
            // different sessions serialize on the mutex inside.
            let consumer = unsafe { TraceConsumer::open(&kernel_session, ptr)? };
            sessions.push(session);
            consumers.push(consumer);
        }

        for guid in &manifest {
            let name = manifest_session_name_in(&prefix, guid);
            let session = EtwSession::start(&name, 0, SessionMode::Normal)?;
            session.enable(guid)?;
            // SAFETY: same as above.
            let consumer = unsafe { TraceConsumer::open(&name, ptr)? };
            sessions.push(session);
            consumers.push(consumer);
        }

        let running = Arc::new(AtomicBool::new(true));
        let mut pumps = Vec::with_capacity(consumers.len());
        for consumer in &consumers {
            let handle = consumer.handle();
            let running_pump = running.clone();
            pumps.push(
                std::thread::Builder::new()
                    .name("etw-pump".into())
                    .spawn(move || {
                        let status = unsafe { ProcessTrace(&[handle], None, None) };
                        if running_pump.load(Ordering::SeqCst) {
                            error!("ProcessTrace exited unexpectedly: {status:?}");
                        }
                    })?,
            );
        }

        Ok(KernelRouter {
            sessions,
            consumers,
            pumps,
            core,
            running,
        })
    }
}

struct RouterCore {
    routes: Vec<(u128, Vec<Target>)>,
    handlers: Vec<Handler>,
    batches: Vec<BatchSlot>,
    sink: Sink,
    scratch: Vec<StateChange>,
}

impl RouterCore {
    fn deliver(&mut self, record: &EVENT_RECORD, now: i64) {
        let provider = record.EventHeader.ProviderId.to_u128();
        let Some((_, targets)) = self.routes.iter().find(|(g, _)| *g == provider) else {
            return;
        };
        let Some(data) = to_user_data(record) else {
            return;
        };
        for &target in targets {
            match target {
                Target::Handler(idx) => {
                    self.scratch.clear();
                    self.handlers[idx](record, data, &mut self.scratch);
                    self.sink.emit_all(self.scratch.drain(..));
                }
                Target::Batch(idx) => {
                    let slot = &mut self.batches[idx];
                    slot.batch.add(record, data);
                    slot.since.get_or_insert(now);
                }
            }
        }
    }

    fn hand_over_due(&mut self, now: i64) {
        for slot in &mut self.batches {
            let Some(since) = slot.since else {
                continue;
            };
            if now - since < slot.window {
                continue;
            }
            slot.since = None;
            if let Some(change) = slot.batch.take() {
                self.sink.emit(change);
            }
        }
    }
}

impl EventSink for RouterCore {
    fn on_event(&mut self, record: &EVENT_RECORD) {
        let now = record.EventHeader.TimeStamp;
        self.deliver(record, now);
        self.hand_over_due(now);
    }
}

pub struct KernelRouter {
    #[allow(dead_code)] // held for Drop (StopTrace after the pumps are joined)
    sessions: Vec<EtwSession>,
    consumers: Vec<TraceConsumer>,
    pumps: Vec<JoinHandle<()>>,
    #[allow(dead_code)] // pump callbacks dereference this via UserContext
    core: Box<parking_lot::Mutex<RouterCore>>,
    running: Arc<AtomicBool>,
}

impl KernelRouter {
    pub fn builder() -> KernelRouterBuilder {
        KernelRouterBuilder {
            flags: 0,
            manifest: Vec::new(),
            handlers: Vec::new(),
            batches: Vec::new(),
            routes: Vec::new(),
            prefix: SESSION_NAME_PREFIX.to_string(),
            kernel_session: KERNEL_SESSION_NAME.to_string(),
        }
    }
}

impl Drop for KernelRouter {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // CloseTrace on every handle: each pump's ProcessTrace returns.
        self.consumers.clear();
        for pump in self.pumps.drain(..) {
            let _ = pump.join();
        }
        // Only now is it safe for `core` and the sessions (StopTrace) to drop.
    }
}

pub fn to_user_data(record: &EVENT_RECORD) -> Option<&[u8]> {
    if record.UserData.is_null() || record.UserDataLength == 0 {
        return None;
    }
    Some(unsafe {
        std::slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize)
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::etw::vars::guid;
    use crate::providers::process::KERNEL_PROCESS_PROVIDER;
    use crate::providers::provider::Provider;
    use windows::Win32::EVENT_TRACE_FLAG_NETWORK_TCPIP;

    /// Only one NT Kernel Logger session can exist at a time, so ETW
    /// integration tests must not run concurrently.
    pub(crate) static ETW_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const TEST_GUID: GUID = guid!("9a280ac0-c8e0-11d1-84e2-00c04fb998a2");

    fn session_exists(name: &str) -> bool {
        let out = std::process::Command::new("logman")
            .args(["query", "-ets"])
            .output()
            .expect("logman query");
        String::from_utf8_lossy(&out.stdout).contains(name)
    }

    /// logman visibility of a freshly started/stopped session is not
    /// instantaneous; poll instead of asserting on a single snapshot.
    fn wait_session(name: &str, want: bool) -> bool {
        for _ in 0..30 {
            if session_exists(name) == want {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }

    const QUIET: GUID = guid!("11111111-2222-3333-4444-555555555555");
    const CHATTY: GUID = guid!("66666666-7777-8888-9999-aaaaaaaaaaaa");

    struct Counting(u32);

    impl Batch for Counting {
        fn add(&mut self, _: &EVENT_RECORD, _: &[u8]) {
            self.0 += 1;
        }

        fn take(&mut self) -> Option<StateChange> {
            let n = std::mem::take(&mut self.0);
            (n > 0).then_some(StateChange::ProcessStopped(n))
        }
    }

    fn event_at(provider: GUID, timestamp: i64, payload: &[u8; 4]) -> EVENT_RECORD {
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProviderId = provider;
        record.EventHeader.TimeStamp = timestamp;
        record.UserData = payload.as_ptr() as *mut _;
        record.UserDataLength = payload.len() as u16;
        record
    }

    #[test]
    fn a_quiet_batch_is_handed_over_on_anyone_elses_event_once_due() {
        let (sink, rx) = Sink::bounded(16);
        let mut core = RouterCore {
            routes: vec![(QUIET.to_u128(), vec![Target::Batch(0)])],
            handlers: Vec::new(),
            batches: vec![BatchSlot {
                batch: Box::new(Counting(0)),
                window: 100,
                since: None,
            }],
            sink,
            scratch: Vec::new(),
        };
        let payload = [0u8; 4];

        core.on_event(&event_at(QUIET, 1_000, &payload));
        core.on_event(&event_at(QUIET, 1_050, &payload));
        core.on_event(&event_at(CHATTY, 1_099, &payload));
        assert!(rx.try_recv().is_err(), "not due before the window has passed");

        core.on_event(&event_at(CHATTY, 1_100, &payload));
        assert!(matches!(rx.try_recv(), Ok(StateChange::ProcessStopped(2))));

        core.on_event(&event_at(CHATTY, 5_000, &payload));
        assert!(rx.try_recv().is_err(), "an empty batch sends nothing");
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn router_drop_leaves_no_session() {
        let _guard = ETW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let manifest_name = manifest_session_name(&KERNEL_PROCESS_PROVIDER);

        let (sink, _rx) = Sink::bounded(16);
        let mut builder = KernelRouter::builder();
        builder
            .kernel_flags(EVENT_TRACE_FLAG_NETWORK_TCPIP)
            .manifest(KERNEL_PROCESS_PROVIDER)
            .on(&[TEST_GUID], |_, _| None)
            .on(&[KERNEL_PROCESS_PROVIDER], |_, _| None);
        let router = builder.start(sink).expect("router start");
        assert!(
            wait_session(KERNEL_SESSION_NAME, true),
            "kernel session should be running after start"
        );
        assert!(
            wait_session(&manifest_name, true),
            "manifest session should be running after start"
        );

        drop(router);
        assert!(
            wait_session(KERNEL_SESSION_NAME, false),
            "kernel session should be gone after drop"
        );
        assert!(
            wait_session(&manifest_name, false),
            "manifest session should be gone after drop"
        );
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_session_left_behind_by_a_killed_agent_does_not_silence_disk_and_samples() {
        let _guard = ETW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::forget(
            crate::etw::session::EtwSession::start(KERNEL_SESSION_NAME, 0, SessionMode::SystemLogger)
                .expect("leftover session"),
        );

        let (sink, rx) = Sink::bounded(1 << 16);
        let mut builder = KernelRouter::builder();
        crate::providers::disk::KernelDiskProvider::new()
            .register(&mut builder)
            .unwrap();
        crate::providers::cpu_sampler::CpuSamplerProvider::new()
            .register(&mut builder)
            .unwrap();
        let router = builder.start(sink).expect("router start");

        let path = std::env::temp_dir().join("uniproc-router-disk-test.bin");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut disk, mut samples) = (false, false);
        while std::time::Instant::now() < deadline && !(disk && samples) {
            std::fs::write(&path, vec![7u8; 1 << 20]).unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .sync_all()
                .unwrap();
            for change in rx.try_iter() {
                match change {
                    StateChange::Disk(_) => disk = true,
                    StateChange::CpuSamples(_) => samples = true,
                    _ => {}
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        drop(router);
        let _ = std::fs::remove_file(&path);

        assert!(disk, "no StateChange::Disk after taking over a leftover kernel session");
        assert!(samples, "no StateChange::CpuSamples after taking over a leftover kernel session");
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn merged_sessions_deliver_events() {
        let _guard = ETW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .try_init();

        let (sink, rx) = Sink::bounded(4096);
        let mut builder = KernelRouter::builder();
        crate::providers::network::KernelNetworkProvider::new()
            .register(&mut builder)
            .unwrap();
        crate::providers::process::KernelProcessProvider::with_queue(
            crossbeam_channel::unbounded(),
            String::new(),
        )
        .register(&mut builder)
        .unwrap();
        let router = builder.start(sink).expect("router start");

        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "exit", "0"])
            .spawn()
            .expect("spawn child");
        let child_pid = child.id();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut total = 0usize;
        let mut network = false;
        let mut process = false;
        while std::time::Instant::now() < deadline && !(network && process) {
            for _ in 0..10 {
                let _ = sock.send_to(b"x", "192.0.2.1:53");
            }
            for change in rx.try_iter() {
                total += 1;
                match change {
                    StateChange::Network(_) => network = true,
                    StateChange::ProcessStarted(e) if e.pid == child_pid => process = true,
                    _ => {}
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = child.wait();
        drop(router);
        eprintln!("total={total} network={network} process={process}");

        assert!(network, "no StateChange::Network on the merged router");
        assert!(process, "no ProcessStarted on the merged router");
    }
}
