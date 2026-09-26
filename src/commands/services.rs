use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::time::Duration;

use windows::Win32::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO,
    SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_PAUSE_CONTINUE,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
    StartServiceW,
};
use windows::core::PCWSTR;

use crate::api::CommandResult;
use crate::commands::vars::{ERROR_SERVICE_NOT_ACTIVE, ERROR_TIMEOUT};
use crate::win::service_handle;

/// Single Win32 error conversion point. `Error::code()` is an HRESULT; for
/// FACILITY_WIN32 extract the low 16 bits, otherwise pass through as-is.
pub fn win32_code(e: &windows::core::Error) -> u32 {
    let hresult = e.code().0 as u32;
    if hresult & 0xFFFF_0000 == 0x8007_0000 {
        hresult & 0xFFFF
    } else {
        hresult
    }
}

#[derive(Clone, Copy)]
pub struct ScHandle(pub SC_HANDLE);

// SAFETY: SCM handles are not thread-affine; the Service Control Manager
// serializes access on its side.
unsafe impl Send for ScHandle {}

pub struct ScManager(ScHandle);

impl ScManager {
    pub fn open() -> Result<Self, u32> {
        let handle = service_handle(unsafe {
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

impl Drop for ScManager {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0.0) };
    }
}

struct ServiceHandleGuard(SC_HANDLE);

impl ServiceHandleGuard {
    fn open(scm: ScHandle, name: &str, access: i32) -> Result<Self, u32> {
        let name_u16: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let handle =
            service_handle(unsafe { OpenServiceW(scm.0, PCWSTR(name_u16.as_ptr()), access as u32) })
                .map_err(|e| win32_code(&e))?;
        Ok(Self(handle))
    }
}

impl Drop for ServiceHandleGuard {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

#[derive(Clone, Copy)]
pub enum ServiceAction {
    Start,
    Stop,
    Pause,
    Resume,
}

pub fn control(scm: ScHandle, name: &str, action: ServiceAction) -> CommandResult {
    let access = match action {
        ServiceAction::Start => SERVICE_START,
        ServiceAction::Stop => SERVICE_STOP | SERVICE_QUERY_STATUS,
        ServiceAction::Pause | ServiceAction::Resume => SERVICE_PAUSE_CONTINUE,
    };
    let service = ServiceHandleGuard::open(scm, name, access)?;

    let mut status = SERVICE_STATUS_PROCESS::default();
    let status_ptr = &mut status as *mut _ as *mut _;
    let result = unsafe {
        match action {
            ServiceAction::Start => StartServiceW(service.0, None),
            ServiceAction::Stop => ControlService(service.0, SERVICE_CONTROL_STOP as u32, status_ptr),
            ServiceAction::Pause => ControlService(service.0, SERVICE_CONTROL_PAUSE as u32, status_ptr),
            ServiceAction::Resume => {
                ControlService(service.0, SERVICE_CONTROL_CONTINUE as u32, status_ptr)
            }
        }
    };

    result.ok().map_err(|e| win32_code(&e))
}

pub fn restart(scm: ScHandle, name: &str) -> CommandResult {
    match control(scm, name, ServiceAction::Stop) {
        Err(code) if code != ERROR_SERVICE_NOT_ACTIVE => return Err(code),
        _ => {}
    }
    wait_for_status(scm, name, SERVICE_STOPPED as u32)?;
    control(scm, name, ServiceAction::Start)
}

fn wait_for_status(scm: ScHandle, name: &str, desired: u32) -> CommandResult {
    let service = ServiceHandleGuard::open(scm, name, SERVICE_QUERY_STATUS)?;

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0;

    for _ in 0..60 {
        unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                Some(&mut status as *mut _ as *mut u8),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            )
        }
        .ok()
        .map_err(|e| win32_code(&e))?;

        if status.dwCurrentState == desired {
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    Err(ERROR_TIMEOUT)
}
