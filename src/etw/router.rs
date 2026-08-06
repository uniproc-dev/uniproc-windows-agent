use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use anyhow::Result;
use tracing::error;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_TRACE_FLAG, ProcessTrace};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{GUID, w};

use crate::etw::consumer::{EventSink, TraceConsumer};
use crate::etw::session::{EtwSession, SessionMode};
use crate::etw::vars::{KERNEL_SESSION_NAME, SESSION_NAME_PREFIX};
use crate::sink::Sink;
use crate::state::events::StateChange;

pub(crate) fn manifest_session_name(guid: &GUID) -> String {
    format!("{SESSION_NAME_PREFIX}{guid:?}").replace(['{', '}'], "")
}

type Handler = Box<dyn FnMut(&EVENT_RECORD, &[u8], &mut Vec<StateChange>) + Send>;

// `From<EVENT_TRACE_FLAG> for u32` is blocked by the orphan rule, so the
// boundary takes a local newtype instead.
pub struct EnableFlags(pub u32);

impl From<EVENT_TRACE_FLAG> for EnableFlags {
    fn from(flags: EVENT_TRACE_FLAG) -> Self {
        Self(flags.0)
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
    routes: HashMap<GUID, Vec<usize>>,
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
        for guid in providers {
            self.routes.entry(*guid).or_default().push(idx);
        }
        self
    }

    /// Legacy MOF providers: NT Kernel Logger session, EnableFlags.
    pub fn kernel_flags(&mut self, flags: impl Into<EnableFlags>) -> &mut Self {
        self.flags |= flags.into().0;
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
            routes,
        } = self;

        let mut core = Box::new(parking_lot::Mutex::new(RouterCore {
            routes,
            handlers,
            sink,
            scratch: Vec::new(),
        }));
        let ptr: *mut parking_lot::Mutex<RouterCore> = &mut *core;

        let mut sessions = Vec::new();
        let mut consumers = Vec::new();

        if flags != 0 {
            unsafe { enable_profile_privilege()? };
            let session = EtwSession::start(KERNEL_SESSION_NAME, flags, SessionMode::SystemLogger)?;
            // SAFETY: ptr points at `core`, which KernelRouter owns and drops
            // only after every pump thread has been joined; callbacks from
            // different sessions serialize on the mutex inside.
            let consumer = unsafe { TraceConsumer::open(KERNEL_SESSION_NAME, ptr)? };
            sessions.push(session);
            consumers.push(consumer);
        }

        for guid in &manifest {
            let name = manifest_session_name(guid);
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
    routes: HashMap<GUID, Vec<usize>>,
    handlers: Vec<Handler>,
    sink: Sink,
    scratch: Vec<StateChange>,
}

impl EventSink for RouterCore {
    fn on_event(&mut self, record: &EVENT_RECORD) {
        let Some(indices) = self.routes.get(&record.EventHeader.ProviderId) else {
            return;
        };
        let Some(data) = to_user_data(record) else {
            return;
        };
        for &idx in indices {
            self.scratch.clear();
            self.handlers[idx](record, data, &mut self.scratch);
            self.sink.emit_all(self.scratch.drain(..));
        }
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
            routes: HashMap::new(),
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

unsafe fn enable_profile_privilege() -> Result<()> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?
    };

    let mut luid = Default::default();
    unsafe { LookupPrivilegeValueW(None, w!("SeSystemProfilePrivilege"), &mut luid)? };

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe { AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)? };
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::etw::vars::guid;
    use crate::providers::process::KERNEL_PROCESS_PROVIDER;
    use crate::providers::provider::Provider;
    use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_NETWORK_TCPIP;

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
        crate::providers::process::KernelProcessProvider::new()
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
