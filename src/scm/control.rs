use std::time::Duration;

use windows::Win32::{
    ControlService, QueryServiceStatusEx, SC_STATUS_PROCESS_INFO, SERVICE_CONTROL_CONTINUE,
    SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_PAUSE_CONTINUE, SERVICE_QUERY_STATUS,
    SERVICE_START, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED, StartServiceW,
};

use crate::api::CommandResult;
use crate::scm::{ERROR_SERVICE_NOT_ACTIVE, ERROR_TIMEOUT, ScHandle, Service};
use crate::win::win32_code;

#[derive(Clone, Copy)]
pub enum ServiceAction {
    Start,
    Stop,
    Pause,
    Resume,
    Restart,
}

pub fn act(scm: ScHandle, name: &str, action: ServiceAction) -> CommandResult {
    match action {
        ServiceAction::Start => start(scm, name),
        ServiceAction::Stop => send(scm, name, SERVICE_CONTROL_STOP, SERVICE_STOP | SERVICE_QUERY_STATUS),
        ServiceAction::Pause => send(scm, name, SERVICE_CONTROL_PAUSE, SERVICE_PAUSE_CONTINUE),
        ServiceAction::Resume => send(scm, name, SERVICE_CONTROL_CONTINUE, SERVICE_PAUSE_CONTINUE),
        ServiceAction::Restart => restart(scm, name),
    }
}

fn start(scm: ScHandle, name: &str) -> CommandResult {
    let service = Service::open(scm, name, SERVICE_START).map_err(|e| win32_code(&e))?;
    unsafe { StartServiceW(service.0, None) }.ok().map_err(|e| win32_code(&e))
}

fn send(scm: ScHandle, name: &str, control: i32, access: i32) -> CommandResult {
    let service = Service::open(scm, name, access).map_err(|e| win32_code(&e))?;
    let mut status = SERVICE_STATUS_PROCESS::default();
    unsafe { ControlService(service.0, control as u32, &mut status as *mut _ as *mut _) }
        .ok()
        .map_err(|e| win32_code(&e))
}

fn restart(scm: ScHandle, name: &str) -> CommandResult {
    match act(scm, name, ServiceAction::Stop) {
        Err(code) if code != ERROR_SERVICE_NOT_ACTIVE => return Err(code),
        _ => {}
    }
    wait_for_status(scm, name, SERVICE_STOPPED as u32)?;
    start(scm, name)
}

fn wait_for_status(scm: ScHandle, name: &str, desired: u32) -> CommandResult {
    let service = Service::open(scm, name, SERVICE_QUERY_STATUS).map_err(|e| win32_code(&e))?;

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0;

    for _ in 0..300 {
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

        std::thread::sleep(Duration::from_millis(100));
    }

    Err(ERROR_TIMEOUT)
}
