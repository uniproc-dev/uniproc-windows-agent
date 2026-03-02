use std::ffi::OsString;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use crate::etw::session::EtwSession;
use crate::logger;

define_windows_service!(ffi_service_main, service_main);


std::thread_local! {
    static SERVICE_NAME_TL: std::cell::RefCell<String> = Default::default();
    static ETW_SESSION_TL:  std::cell::RefCell<String> = Default::default();
}

pub fn run_as_service(service_name: &str, etw_session_name: &str) -> Result<()> {
    SERVICE_NAME_TL.with(|s| *s.borrow_mut() = service_name.to_string());
    ETW_SESSION_TL.with(|s| *s.borrow_mut() = etw_session_name.to_string());

    service_dispatcher::start(service_name, ffi_service_main)
        .context("Failed to start service dispatcher")
}

fn service_main(arguments: Vec<OsString>) {
    logger::init_console();

    let service_name  = SERVICE_NAME_TL.with(|s| s.borrow().clone());
    let etw_session   = ETW_SESSION_TL.with(|s| s.borrow().clone());

    if let Err(e) = run_service(arguments, &service_name, &etw_session) {
        error!("Service exited with error: {e:#}");
    }
}

fn run_service(_args: Vec<OsString>, service_name: &str, etw_session_name: &str) -> Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Stop signal received from SCM");
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(service_name, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type:      ServiceType::OWN_PROCESS,
        current_state:     ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code:         ServiceExitCode::Win32(0),
        checkpoint:        0,
        wait_hint:         Duration::from_secs(5),
        process_id:        None,
    })?;

    let session = Arc::new(EtwSession::new(etw_session_name));
    let session_for_thread = Arc::clone(&session);

    let etw_thread = std::thread::spawn(move || {
        if let Err(e) = session_for_thread.start_monitoring() {
            error!("ETW session error: {e:#}");
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type:      ServiceType::OWN_PROCESS,
        current_state:     ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code:         ServiceExitCode::Win32(0),
        checkpoint:        0,
        wait_hint:         Duration::from_secs(0),
        process_id:        None,
    })?;

    info!("ETW Process Monitor service started.");
    let _ = stop_rx.recv();
    info!("Shutting down ETW session...");

    session.stop_monitoring();
    let _ = etw_thread.join();

    status_handle.set_service_status(ServiceStatus {
        service_type:      ServiceType::OWN_PROCESS,
        current_state:     ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code:         ServiceExitCode::Win32(0),
        checkpoint:        0,
        wait_hint:         Duration::from_secs(0),
        process_id:        None,
    })?;

    Ok(())
}

pub fn run_direct(etw_session_name: &str) -> Result<()> {
    info!("Starting ETW monitoring session. Press Ctrl+C to stop.");

    let session = Arc::new(EtwSession::new(etw_session_name));
    let session_clone = Arc::clone(&session);
    let main_thread = std::thread::current();

    ctrlc::set_handler(move || {
        session_clone.stop_monitoring();
        info!("Stopping ETW monitoring session. 1");
        main_thread.unpark();
    })?;

    session.start_monitoring()?;
    std::thread::park();
    info!("Stopping ETW monitoring session. 2");

    Ok(())
}

pub fn install(service_name: &str, display_name: &str, description: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let service = manager.create_service(
        &ServiceInfo {
            name:             OsString::from(service_name),
            display_name:     OsString::from(display_name),
            service_type:     ServiceType::OWN_PROCESS,
            start_type:       ServiceStartType::AutoStart,
            error_control:    ServiceErrorControl::Normal,
            executable_path:  std::env::current_exe()?,
            launch_arguments: vec![],
            dependencies:     vec![],
            account_name:     None,
            account_password: None,
        },
        ServiceAccess::CHANGE_CONFIG,
    )?;

    service.set_description(description)?;
    Ok(())
}

pub fn uninstall(service_name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )?;

    let service = manager.open_service(service_name, ServiceAccess::DELETE | ServiceAccess::STOP)?;
    let _ = service.stop();
    service.delete()?;
    Ok(())
}