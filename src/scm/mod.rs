mod control;
mod inventory;

use std::sync::Arc;

use parking_lot::Mutex;
use windows::Win32::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE,
};
use windows::core::{Error, PCWSTR};

use crate::win::win32_code;

pub use control::{ServiceAction, control, restart};
pub use inventory::Inventory;

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

fn checked(handle: SC_HANDLE) -> windows::core::Result<SC_HANDLE> {
    if handle.0.is_null() {
        Err(Error::from_thread())
    } else {
        Ok(handle)
    }
}
