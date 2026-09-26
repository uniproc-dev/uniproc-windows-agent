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
}

pub fn control(scm: ScHandle, name: &str, action: ServiceAction) -> CommandResult {
    let access = match action {
        ServiceAction::Start => SERVICE_START,
        ServiceAction::Stop => SERVICE_STOP | SERVICE_QUERY_STATUS,
        ServiceAction::Pause | ServiceAction::Resume => SERVICE_PAUSE_CONTINUE,
    };
    let service = Service::open(scm, name, access).map_err(|e| win32_code(&e))?;

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
    let service = Service::open(scm, name, SERVICE_QUERY_STATUS).map_err(|e| win32_code(&e))?;

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
