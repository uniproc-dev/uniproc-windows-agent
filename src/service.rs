use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::logger;
use crate::monitor;

define_windows_service!(ffi_service_main, service_main);

std::thread_local! {
    static SERVICE_NAME_TL: std::cell::RefCell<String> = Default::default();
}

pub fn run_as_service(service_name: &str) -> Result<()> {
    SERVICE_NAME_TL.with(|s| *s.borrow_mut() = service_name.to_string());
    service_dispatcher::start(service_name, ffi_service_main)
        .context("Failed to start service dispatcher")
}

fn service_main(_arguments: Vec<OsString>) {
    logger::init_console();
    let service_name = SERVICE_NAME_TL.with(|s| s.borrow().clone());
    if let Err(e) = run_service(&service_name) {
        error!("Service exited with error: {e:#}");
    }
}

fn run_service(service_name: &str) -> Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    let status_handle =
        service_control_handler::register(service_name, move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    set_status(&status_handle, ServiceState::StartPending)?;

    monitor::run(|| {
        set_status(&status_handle, ServiceState::Running).ok();
        stop_rx.recv().ok();
    })?;

    set_status(&status_handle, ServiceState::Stopped)
}

fn set_status(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
) -> Result<()> {
    let (controls, wait_hint) = match state {
        ServiceState::Running => (
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            Duration::ZERO,
        ),
        ServiceState::StartPending => (ServiceControlAccept::empty(), Duration::from_secs(5)),
        _ => (ServiceControlAccept::empty(), Duration::ZERO),
    };
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    })?;
    Ok(())
}

pub fn run_direct() -> Result<()> {
    info!("Starting monitoring (press Ctrl+C to stop).");
    monitor::run(|| {
        let main_thread = std::thread::current();
        ctrlc::set_handler(move || {
            info!("Ctrl+C received, stopping…");
            main_thread.unpark();
        })
        .ok();
        std::thread::park();
    })
}

pub fn install(service_name: &str, display_name: &str, description: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let service = manager.create_service(
        &ServiceInfo {
            name: OsString::from(service_name),
            display_name: OsString::from(display_name),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        },
        ServiceAccess::CHANGE_CONFIG,
    )?;
    service.set_description(description)?;
    Ok(())
}

pub fn uninstall(service_name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service =
        manager.open_service(service_name, ServiceAccess::DELETE | ServiceAccess::STOP)?;
    let _ = service.stop();
    service.delete()?;
    Ok(())
}
