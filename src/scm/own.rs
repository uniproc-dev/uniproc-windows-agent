//! The agent's own service as a client sees it through the SCM: whether it
//! runs, how far a start or a stop has come, and starting or stopping it.

use crate::bindings::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, DACL_SECURITY_INFORMATION, GetLastError, HANDLE, LocalFree,
    PSECURITY_DESCRIPTOR, READ_CONTROL, SECURITY_INFORMATION, SERVICE_QUERY_STATUS, SetServiceObjectSecurity, WRITE_DAC,
};
use windows_core::w;

use super::control::{self, ServiceAction};
use super::{Connection, Service};
use crate::api::{CommandResult, START_STEPS, STOP_STEPS, SERVICE_NAME, ServiceState, ServiceStatus};
use crate::win::win32_code;

/// Windows' default DACL for a service, but for interactive users, who may
/// also start (RP) and stop (WP) it.
const INTERACTIVE_USERS_CONTROL: windows_core::PCWSTR = w!(
    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
);

const SDDL_REVISION_1: u32 = 1;

/// The service's status now; Err with the Win32 code when it cannot be
/// read, 1060 when the service is not installed.
pub fn status() -> Result<ServiceStatus, u32> {
    status_of(SERVICE_NAME)
}

fn status_of(name: &str) -> Result<ServiceStatus, u32> {
    let scm = Connection::open()?;
    let service = Service::open(scm.handle(), name, SERVICE_QUERY_STATUS).map_err(|e| win32_code(&e))?;
    service.status().ok_or_else(|| unsafe { GetLastError() })
}

/// How far a pending start or stop has come, from 0 to 1, counted in
/// [`START_STEPS`] or [`STOP_STEPS`]; None while neither is pending.
pub fn progress(status: &ServiceStatus) -> Option<f32> {
    let steps = match status.state {
        ServiceState::StartPending => START_STEPS,
        ServiceState::StopPending => STOP_STEPS,
        _ => return None,
    };
    Some(status.checkpoint.min(steps) as f32 / steps as f32)
}

/// Lets every user logged on interactively start and stop the service;
/// the rest of its DACL is Windows' default. Takes WRITE_DAC: an
/// administrator, or the service itself.
pub fn let_interactive_users_control() -> Result<(), u32> {
    let_interactive_users_control_of(SERVICE_NAME)
}

fn let_interactive_users_control_of(name: &str) -> Result<(), u32> {
    let scm = Connection::open()?;
    let service = Service::open(scm.handle(), name, WRITE_DAC | READ_CONTROL).map_err(|e| win32_code(&e))?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(INTERACTIVE_USERS_CONTROL, SDDL_REVISION_1, &mut descriptor, None) }
        .ok()
        .map_err(|e| win32_code(&e))?;
    let set = unsafe { SetServiceObjectSecurity(service.0, SECURITY_INFORMATION(DACL_SECURITY_INFORMATION as u32), descriptor) }
        .ok()
        .map_err(|e| win32_code(&e));
    unsafe { LocalFree(HANDLE(descriptor.0)) };
    set
}

/// Asks the SCM to start the service; [`status`] tells how far it came.
pub fn start() -> CommandResult {
    control::act(Connection::open()?.handle(), SERVICE_NAME, ServiceAction::Start)
}

/// Asks the SCM to stop the service; [`status`] tells how far it came.
pub fn stop() -> CommandResult {
    control::act(Connection::open()?.handle(), SERVICE_NAME, ServiceAction::Stop)
}

/// Stops the service, waits up to half a minute for it to stop, then asks
/// the SCM to start it; blocks until then. [`status`] tells, from another
/// thread, how far it came.
pub fn restart() -> CommandResult {
    control::act(Connection::open()?.handle(), SERVICE_NAME, ServiceAction::Restart)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{START_STEPS, STOP_STEPS, ServiceState};

    fn at(state: ServiceState, checkpoint: u32) -> ServiceStatus {
        ServiceStatus {
            state,
            checkpoint,
            ..Default::default()
        }
    }

    #[test]
    fn a_pending_start_or_stop_counts_its_steps() {
        assert_eq!(progress(&at(ServiceState::StartPending, 0)), Some(0.0));
        assert_eq!(progress(&at(ServiceState::StartPending, 2)), Some(2.0 / START_STEPS as f32));
        assert_eq!(progress(&at(ServiceState::StopPending, 1)), Some(1.0 / STOP_STEPS as f32));
        assert_eq!(progress(&at(ServiceState::StartPending, START_STEPS + 3)), Some(1.0), "never past the end");
        assert_eq!(progress(&at(ServiceState::Running, 0)), None);
        assert_eq!(progress(&at(ServiceState::Stopped, 0)), None);
    }

    fn sddl(name: &str) -> String {
        let output = std::process::Command::new("sc.exe").args(["sdshow", name]).output().unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    #[test]
    #[ignore = "requires admin: creates and deletes a service"]
    fn interactive_users_may_start_and_stop_the_service_and_nothing_more() {
        let name = "UniprocDaclTest";
        let _ = std::process::Command::new("sc.exe").args(["delete", name]).output();
        let created = std::process::Command::new("sc.exe")
            .args(["create", name, "binPath=", r"C:\Windows\System32\cmd.exe"])
            .output()
            .unwrap();
        assert!(created.status.success(), "{}", String::from_utf8_lossy(&created.stdout));
        let before = sddl(name);
        let applied = let_interactive_users_control_of(name);
        let after = sddl(name);
        let _ = std::process::Command::new("sc.exe").args(["delete", name]).output();
        assert_eq!(applied, Ok(()));
        assert!(before.contains("(A;;CCLCSWLOCRRC;;;IU)"), "{before}");
        assert!(after.contains("(A;;CCLCSWRPWPLOCRRC;;;IU)"), "{after}");
        assert!(after.contains(";;;BA)") && after.contains(";;;SY)"), "{after}");
    }

    #[test]
    fn any_user_reads_a_service_s_status_and_a_missing_one_is_1060() {
        let event_log = status_of("EventLog");
        assert_eq!(event_log.map(|s| s.state), Ok(ServiceState::Running));
        assert!(event_log.is_ok_and(|s| s.pid != 0));
        assert_eq!(status_of("UniprocNoSuchService").map(|s| s.state), Err(1060));
    }
}
