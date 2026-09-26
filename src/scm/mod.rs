mod control;
mod inventory;
mod watch;

use std::sync::Arc;

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

pub use control::{ServiceAction, control, restart};
pub use inventory::Inventory;
pub use watch::{ServiceWatch, Watcher, Watching};

/// Win32 ERROR_SERVICE_NOT_ACTIVE: stop on an already stopped service.
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
/// Win32 ERROR_TIMEOUT: service did not reach the desired state in time.
const ERROR_TIMEOUT: u32 = 1460;

/// The agent's one connection to the Service Control Manager, opened on
/// first use and shared by the inventory and the service commands.
#[derive(Clone, Default)]
pub struct Scm {
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
