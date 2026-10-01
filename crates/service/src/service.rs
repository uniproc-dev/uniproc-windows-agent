use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use uniproc_windows_agent::api::SERVICE_NAME;
use uniproc_windows_agent::local::Local;
use uniproc_windows_http::Telemetry;

use crate::logger;

define_windows_service!(ffi_service_main, service_main);

/// Starts the agent and binds its pipe, then calls `stop`, which returns
/// when the agent is to stop. Fails before calling `stop` when either
/// cannot start.
fn run(telemetry: Telemetry, stop: impl FnOnce()) -> Result<()> {
    let agent = std::sync::Arc::new(Local::start_as_service()?);

    match uniproc_windows_http::serve(agent.clone(), telemetry) {
        Ok(access) => info!(
            url = access.url,
            access = %uniproc_windows_http::access_path().display(),
            "state API listening"
        ),
        Err(error) => tracing::warn!(%error, "the state API did not start"),
    }

    let (bound_tx, bound) = mpsc::channel::<Result<()>>();
    let node_agent = agent.clone();
    std::thread::Builder::new().name("rpc".into()).spawn(move || {
        let runtime = match compio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = bound_tx.send(Err(anyhow::anyhow!("no runtime for the pipe: {e}")));
                return;
            }
        };
        runtime.block_on(async move {
            let listener = match uniproc_windows_rpc::listen().await {
                Ok(listener) => listener,
                Err(e) => {
                    let _ = bound_tx.send(Err(e));
                    return;
                }
            };
            let _ = bound_tx.send(Ok(()));
            if let Err(e) = uniproc_windows_rpc::serve(&listener, node_agent).await {
                error!("the agent's pipe stopped: {e:#}");
            }
        });
    })?;
    if let Err(e) = bound.recv().map_err(|_| anyhow::anyhow!("the pipe's thread ended")).and_then(|r| r) {
        agent.stop();
        return Err(e);
    }

    info!("Uniproc monitor running");

    stop();

    info!("Shutting down…");
    agent.stop();
    Ok(())
}

pub fn run_as_service() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start service dispatcher")
}

fn service_main(_arguments: Vec<OsString>) {
    let telemetry = logger::init_service();
    if let Err(e) = run_service(SERVICE_NAME, telemetry) {
        error!("Service exited with error: {e:#}");
    }
}

/// Exit code the SCM shows when the agent could not start; the reason is
/// in the agent's log.
const START_FAILED: u32 = 1;

fn run_service(service_name: &str, telemetry: Telemetry) -> Result<()> {
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

    set_status(&status_handle, ServiceState::StartPending, ServiceExitCode::Win32(0))?;

    let ran = run(telemetry, || {
        set_status(&status_handle, ServiceState::Running, ServiceExitCode::Win32(0)).ok();
        stop_rx.recv().ok();
    });
    let exit_code = match &ran {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(START_FAILED),
    };
    set_status(&status_handle, ServiceState::Stopped, exit_code)?;
    ran
}

fn set_status(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    exit_code: ServiceExitCode,
) -> Result<()> {
    let (controls, wait_hint) = match state {
        ServiceState::Running => (
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            Duration::ZERO,
        ),
        ServiceState::StartPending => (ServiceControlAccept::empty(), Duration::from_secs(90)),
        _ => (ServiceControlAccept::empty(), Duration::ZERO),
    };
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    })?;
    Ok(())
}

pub fn run_direct(telemetry: Telemetry) -> Result<()> {
    info!("Starting monitoring (press Ctrl+C to stop).");
    run(telemetry, || {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_handler = stop.clone();
        let main_thread = std::thread::current();
        ctrlc::set_handler(move || {
            info!("Ctrl+C received, stopping…");
            stop_handler.store(true, std::sync::atomic::Ordering::SeqCst);
            main_thread.unpark();
        })
        .ok();
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::park();
        }
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
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service.set_description(description)?;
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(10),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart, ServiceAction {
            action_type: ServiceActionType::None,
            delay: Duration::ZERO,
        }]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

/// Stops the service, waits up to a minute for it to stop, deletes it, and
/// stops the trace sessions a killed service left behind, which it names.
pub fn uninstall(service_name: &str) -> Result<Vec<String>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        service_name,
        ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    )?;
    let _ = service.stop();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while service.query_status()?.current_state != ServiceState::Stopped {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("{service_name} did not stop within a minute");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    service.delete()?;
    Ok(uniproc_windows_agent::stop_leftover_sessions())
}
