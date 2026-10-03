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
use uniproc_windows_agent::local::{Local, Started};
use uniproc_windows_http::Telemetry;

use crate::logger;

define_windows_service!(ffi_service_main, service_main);

/// Starts the agent and binds its pipe, then calls `stop`, which returns
/// when the agent is to stop. Fails before calling `stop` when either
/// cannot start. `tell` hears each step as it is reached.
fn run(telemetry: Telemetry, tell: &mut dyn FnMut(Step), stop: impl FnOnce()) -> Result<()> {
    let agent = std::sync::Arc::new(Local::start_as_service(&mut |started| tell(Step::Core(started)))?);

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
    tell(Step::Running);

    stop();

    tell(Step::Stopping);
    info!("Shutting down…");
    agent.stop();
    tell(Step::CoreStopped);
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

    let mut tell = |step| {
        info!(?step, "the service is at");
        let (state, checkpoint, next_within) = told(step);
        if let Err(error) = set_status(&status_handle, state, checkpoint, next_within, ServiceExitCode::Win32(0)) {
            tracing::warn!(error = format!("{error:#}"), ?step, "the SCM was not told");
        }
    };
    tell(Step::Registered);
    if let Err(error) = uniproc_windows_agent::agent_service::let_interactive_users_control() {
        tracing::warn!(error, "only administrators can start and stop the service");
    }

    let ran = run(telemetry, &mut tell, || {
        stop_rx.recv().ok();
    });
    let exit_code = match &ran {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(START_FAILED),
    };
    set_status(&status_handle, ServiceState::Stopped, 0, Duration::ZERO, exit_code)?;
    ran
}

fn set_status(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
    wait_hint: Duration,
    exit_code: ServiceExitCode,
) -> Result<()> {
    let controls = match state {
        ServiceState::Running => ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        _ => ServiceControlAccept::empty(),
    };
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    })?;
    Ok(())
}

/// Where the service is, as the SCM is told it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Registered,
    Core(Started),
    Running,
    Stopping,
    CoreStopped,
}

/// The state, the checkpoint and how long until the next step that the
/// SCM is told at `step`.
fn told(step: Step) -> (ServiceState, u32, Duration) {
    let seconds = Duration::from_secs;
    match step {
        Step::Registered => (ServiceState::StartPending, 0, seconds(10)),
        Step::Core(Started::SignatureCache) => (ServiceState::StartPending, 1, seconds(30)),
        Step::Core(Started::Sessions) => (ServiceState::StartPending, 2, seconds(30)),
        Step::Core(Started::FirstSnapshot) => (ServiceState::StartPending, 3, seconds(60)),
        Step::Core(Started::Verdicts) => (ServiceState::StartPending, 4, seconds(10)),
        Step::Running => (ServiceState::Running, 0, Duration::ZERO),
        Step::Stopping => (ServiceState::StopPending, 0, seconds(30)),
        Step::CoreStopped => (ServiceState::StopPending, 1, seconds(5)),
    }
}

pub fn run_direct(telemetry: Telemetry) -> Result<()> {
    info!("Starting monitoring (press Ctrl+C to stop).");
    run(telemetry, &mut |_| {}, || {
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
    uniproc_windows_agent::agent_service::let_interactive_users_control()
        .map_err(|code| anyhow::anyhow!("interactive users were not let start and stop the service: Win32 {code}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use uniproc_windows_agent::api::{START_STEPS, STOP_STEPS};

    #[test]
    fn the_scm_hears_every_step_counted_up_to_its_total() {
        let count = |steps: &[Step], state: ServiceState| {
            steps
                .iter()
                .map(|&step| {
                    let (told_state, checkpoint, next_within) = told(step);
                    assert_eq!(told_state, state, "{step:?}");
                    assert!(!next_within.is_zero(), "{step:?} says how long the next step may take");
                    checkpoint
                })
                .collect::<Vec<_>>()
        };
        let start = [
            Step::Registered,
            Step::Core(Started::SignatureCache),
            Step::Core(Started::Sessions),
            Step::Core(Started::FirstSnapshot),
            Step::Core(Started::Verdicts),
        ];
        assert_eq!(count(&start, ServiceState::StartPending), (0..START_STEPS).collect::<Vec<_>>());
        assert_eq!(told(Step::Running), (ServiceState::Running, 0, Duration::ZERO));
        let stop = [Step::Stopping, Step::CoreStopped];
        assert_eq!(count(&stop, ServiceState::StopPending), (0..STOP_STEPS).collect::<Vec<_>>());
    }
}
