mod control;
mod inventory;
pub mod own;
mod watch;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use windows::Win32::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO,
    SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS_PROCESS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
};
use windows::core::{Error, PCWSTR};

use crate::api::{ServiceState, ServiceStatus};
use crate::win::win32_code;

pub use control::ServiceAction;
pub use watch::ServiceWatch;

use crate::api::{CommandResult, ServiceStats};
use inventory::Inventory;
use watch::{Watcher, Watching};

/// What the services tell the agent's picture.
pub enum ServiceEvent {
    /// A whole scan of the services.
    Scan(Vec<ServiceStats>),
    /// A followed service's status as it changes; None once it is no longer
    /// followed. It wins over a scan taken before the change.
    Status(String, Option<ServiceStatus>),
}

/// The machine's services as the agent sees them: a scan every few seconds,
/// and a close watch on the services someone follows. Stops when dropped;
/// the [`ServiceControl`] it hands out stays usable.
pub struct Services {
    _inventory: Inventory,
    _watcher: Watcher,
    control: ServiceControl,
}

/// Follows and controls single services; cheap to clone.
#[derive(Clone)]
pub struct ServiceControl {
    scm: Scm,
    watching: Watching,
}

impl Services {
    /// `tell` gets every scan and every followed service's change; the
    /// first scan before this returns.
    pub fn start(tell: impl Fn(ServiceEvent) + Clone + Send + 'static) -> std::io::Result<Self> {
        let scm = Scm::new();
        let inventory = Inventory::start(scm.clone(), {
            let tell = tell.clone();
            move |services| tell(ServiceEvent::Scan(services))
        })?;
        let watcher = Watcher::start(scm.clone(), move |name, status| {
            tell(ServiceEvent::Status(name.to_string(), status.copied()))
        })?;
        let control = ServiceControl {
            scm,
            watching: watcher.watching(),
        };
        Ok(Self {
            _inventory: inventory,
            _watcher: watcher,
            control,
        })
    }

    pub fn control(&self) -> ServiceControl {
        self.control.clone()
    }
}

impl ServiceControl {
    /// The service's status now, then every change until the stream is dropped.
    pub fn watch(&self, name: &str) -> ServiceWatch {
        self.watching.watch(name)
    }

    /// Acts on the service and, when that went through, keeps it followed for
    /// `follow_for`, so its transition shows as it happens.
    pub fn act(&self, name: &str, follow_for: Duration, action: ServiceAction) -> CommandResult {
        let hold = self.watching.hold(name, follow_for);
        let result = control::act(self.scm.connection()?.handle(), name, action);
        if result.is_ok() {
            hold.keep();
        }
        result
    }
}

/// Win32 ERROR_SERVICE_NOT_ACTIVE: stop on an already stopped service.
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
/// Win32 ERROR_TIMEOUT: service did not reach the desired state in time.
const ERROR_TIMEOUT: u32 = 1460;

/// The agent's one connection to the Service Control Manager, opened on
/// first use and shared by the inventory, the watcher and the commands.
#[derive(Clone, Default)]
struct Scm {
    connection: Arc<Mutex<Option<Arc<Connection>>>>,
}

impl Scm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens the connection if nothing has yet; a failed open is tried again next time.
    pub fn connection(&self) -> Result<Arc<Connection>, u32> {
        let mut held = self.connection.lock();
        if let Some(connection) = &*held {
            return Ok(connection.clone());
        }
        let connection = Arc::new(Connection::open()?);
        *held = Some(connection.clone());
        Ok(connection)
    }
}

#[derive(Clone, Copy)]
pub struct ScHandle(SC_HANDLE);

unsafe impl Send for ScHandle {}
unsafe impl Sync for ScHandle {}

pub struct Connection(ScHandle);

impl Connection {
    fn open() -> Result<Self, u32> {
        let handle = checked(unsafe {
            OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                (SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) as u32,
            )
        })
        .map_err(|e| win32_code(&e))?;
        Ok(Self(ScHandle(handle)))
    }

    pub fn handle(&self) -> ScHandle {
        self.0
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0.0) };
    }
}

struct Service(SC_HANDLE);

impl Service {
    fn open(scm: ScHandle, name: &str, access: i32) -> windows::core::Result<Self> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        checked(unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), access as u32) }).map(Self)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

impl Service {
    fn status(&self) -> Option<ServiceStatus> {
        let mut raw = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        unsafe {
            QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                Some(&mut raw as *mut _ as *mut u8),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        }
        .ok()
        .ok()?;
        Some(status(&raw))
    }
}

fn state(raw: u32) -> ServiceState {
    match raw as i32 {
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_START_PENDING => ServiceState::StartPending,
        SERVICE_STOP_PENDING => ServiceState::StopPending,
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_CONTINUE_PENDING => ServiceState::ContinuePending,
        SERVICE_PAUSE_PENDING => ServiceState::PausePending,
        SERVICE_PAUSED => ServiceState::Paused,
        _ => ServiceState::Unknown,
    }
}

fn status(raw: &SERVICE_STATUS_PROCESS) -> ServiceStatus {
    ServiceStatus {
        state: state(raw.dwCurrentState),
        pid: raw.dwProcessId,
        exit_code: raw.dwWin32ExitCode,
        service_exit_code: raw.dwServiceSpecificExitCode,
        checkpoint: raw.dwCheckPoint,
        wait_hint_ms: raw.dwWaitHint,
    }
}

fn checked(handle: SC_HANDLE) -> windows::core::Result<SC_HANDLE> {
    if handle.0.is_null() {
        Err(Error::from_thread())
    } else {
        Ok(handle)
    }
}
