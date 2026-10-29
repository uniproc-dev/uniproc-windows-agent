use std::collections::HashMap;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{RecvTimeoutError, Sender};
use crate::bindings::{
    ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfig2W, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_DESCRIPTIONW, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_DELAYED_AUTO_START_INFO,
};
use windows_core::PCWSTR;

use crate::api::{ServiceStats, ServiceStartType};
use crate::scm::{ScHandle, Scm, Service, state};
use crate::win::win32_code;

/// How often the inventory is taken again.
const INTERVAL: Duration = Duration::from_secs(5);

/// Takes the service inventory every few seconds, handing each scan over
/// whole. Stops when dropped.
pub struct Inventory {
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Inventory {
    /// The first scan is handed over before this returns.
    pub fn start(
        scm: Scm,
        mut publish: impl FnMut(Vec<ServiceStats>) + Send + 'static,
    ) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        let mut configs = HashMap::new();
        let mut take = move |publish: &mut dyn FnMut(Vec<ServiceStats>)| {
            if let Ok(connection) = scm.connection()
                && let Some(services) = scan(connection.handle(), &mut buf, &mut configs)
            {
                publish(services);
            }
        };
        take(&mut publish);

        let (stop, stopped) = crossbeam_channel::bounded::<()>(0);
        let thread = std::thread::Builder::new()
            .name("service-inventory".into())
            .spawn(move || {
                while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(INTERVAL) {
                    take(&mut publish);
                }
            })?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Inventory {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Config {
    load_group: String,
    description: String,
    image_path: String,
    /// The process the service ran in when this was read.
    pid: u32,
    startup_type: ServiceStartType,
    delayed_auto: bool,
    account: String,
    read_at: Option<Instant>,
}

/// None when the services could not be listed.
fn scan(scm: ScHandle, buf: &mut Vec<u64>, configs: &mut HashMap<String, Config>) -> Option<Vec<ServiceStats>> {
    let mut services = enumerate(scm, buf)?;
    describe(scm, &mut services, configs);
    Some(services)
}

fn describe(scm: ScHandle, services: &mut [ServiceStats], configs: &mut HashMap<String, Config>) {
    for service in services.iter_mut() {
        let current = configs.get(&service.name).is_some_and(|c| {
            c.pid == service.pid && c.read_at.is_some_and(|at| at.elapsed() < Duration::from_secs(30))
        });
        if !current && let Some(read) = config(scm, &service.name) {
            configs.insert(service.name.clone(), Config { pid: service.pid, ..read });
        }
        if let Some(config) = configs.get(&service.name) {
            service.load_group = config.load_group.clone();
            service.description = config.description.clone();
            service.image_path = config.image_path.clone();
            service.startup_type = config.startup_type;
            service.delayed_auto = config.delayed_auto;
            service.account = config.account.clone();
        }
    }
    configs.retain(|name, _| services.iter().any(|s| &s.name == name));
}

fn aligned_bytes(len: u32) -> Vec<u64> {
    vec![0u64; (len.div_ceil(8) as usize).max(1)]
}

unsafe fn as_byte_slice(buf: &mut [u64], len: u32) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, len as usize) }
}

/// None when the service cannot be opened or its configuration read; a
/// description that cannot be read is left empty.
fn config(scm: ScHandle, name: &str) -> Option<Config> {
    let mut out = Config::default();
    let service = Service::open(scm, name, SERVICE_QUERY_CONFIG).ok()?;

    unsafe {
        let mut size = 0u32;
        let _ = QueryServiceConfigW(service.0, None, 0, &mut size);
        if size == 0 {
            return None;
        }
        let mut storage = aligned_bytes(size);
        let config = storage.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if !QueryServiceConfigW(service.0, Some(config), size, &mut size).as_bool() {
            return None;
        }
        out.load_group = (*config).lpLoadOrderGroup.to_string().unwrap_or_default();
        out.image_path = (*config).lpBinaryPathName.to_string().unwrap_or_default();
        out.startup_type = startup_type((*config).dwStartType);
        out.account = (*config).lpServiceStartName.to_string().unwrap_or_default();
        let mut delayed = SERVICE_DELAYED_AUTO_START_INFO::default();
        let mut needed = 0;
        if QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO as u32,
            Some((&mut delayed as *mut SERVICE_DELAYED_AUTO_START_INFO).cast()),
            size_of::<SERVICE_DELAYED_AUTO_START_INFO>() as u32,
            &mut needed,
        )
        .as_bool()
        {
            out.delayed_auto = delayed.fDelayedAutostart.as_bool();
        } else if out.startup_type == ServiceStartType::Automatic {
            out.startup_type = ServiceStartType::Unknown;
        }

        let level = SERVICE_CONFIG_DESCRIPTION as u32;
        let mut size = 0u32;
        let _ = QueryServiceConfig2W(service.0, level, None, 0, &mut size);
        if size > 0 {
            let mut storage = aligned_bytes(size);
            if QueryServiceConfig2W(
                service.0,
                level,
                Some(as_byte_slice(&mut storage, size).as_mut_ptr()),
                size,
                &mut size,
            )
            .as_bool()
            {
                let desc = storage.as_ptr() as *const SERVICE_DESCRIPTIONW;
                let ptr = (*desc).lpDescription;
                if !ptr.is_null() {
                    out.description = ptr.to_string().unwrap_or_default();
                }
            }
        }
    }

    out.read_at = Some(Instant::now());
    Some(out)
}

fn startup_type(value: u32) -> ServiceStartType {
    match value {
        0 => ServiceStartType::Boot,
        1 => ServiceStartType::System,
        2 => ServiceStartType::Automatic,
        3 => ServiceStartType::Manual,
        4 => ServiceStartType::Disabled,
        _ => ServiceStartType::Unknown,
    }
}

/// Win32 ERROR_MORE_DATA: services came between sizing the buffer and filling it.
const ERROR_MORE_DATA: u32 = 234;
/// How many times the buffer is sized again before a scan is given up.
const LIST_ATTEMPTS: usize = 4;
/// Room for services added between sizing the buffer and filling it.
const LIST_SLACK: u32 = 4096;

/// Every Win32 service with its current state; `buf` keeps its capacity
/// across calls. None when they could not be listed.
fn enumerate(scm: ScHandle, buf: &mut Vec<u64>) -> Option<Vec<ServiceStats>> {
    for _ in 0..LIST_ATTEMPTS {
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume = 0u32;
        let size = (buf.len() * size_of::<u64>()) as u32;
        let listed = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 as u32,
                SERVICE_STATE_ALL as u32,
                (size > 0).then(|| as_byte_slice(buf, size).as_mut_ptr()),
                size,
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
        }
        .ok();
        match listed {
            Ok(()) => return Some(unsafe { entries(buf, services_returned) }),
            Err(error) if win32_code(&error) == ERROR_MORE_DATA => {
                buf.clear();
                buf.resize((bytes_needed + LIST_SLACK).div_ceil(8) as usize, 0);
            }
            Err(_) => return None,
        }
    }
    None
}

/// The first `count` entries EnumServicesStatusExW wrote into `buf`.
unsafe fn entries(buf: &[u64], count: u32) -> Vec<ServiceStats> {
    let entries =
        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize) };
    entries
        .iter()
        .map(|e| ServiceStats {
            name: unsafe { e.lpServiceName.to_string() }.unwrap_or_default(),
            display_name: unsafe { e.lpDisplayName.to_string() }.unwrap_or_default(),
            pid: e.ServiceStatusProcess.dwProcessId,
            state: state(e.ServiceStatusProcess.dwCurrentState),
            service_type: e.ServiceStatusProcess.dwServiceType,
            accepted_controls: e.ServiceStatusProcess.dwControlsAccepted,
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServiceState;

    #[test]
    fn scm_start_types_preserve_unknown_values() {
        assert_eq!(startup_type(0), ServiceStartType::Boot);
        assert_eq!(startup_type(1), ServiceStartType::System);
        assert_eq!(startup_type(2), ServiceStartType::Automatic);
        assert_eq!(startup_type(3), ServiceStartType::Manual);
        assert_eq!(startup_type(4), ServiceStartType::Disabled);
        assert_eq!(startup_type(u32::MAX), ServiceStartType::Unknown);
    }

    #[test]
    fn running_service_exposes_startup_account_and_status_controls() {
        let scm = Scm::new();
        let connection = scm.connection().unwrap();
        let services = scan(connection.handle(), &mut Vec::new(), &mut HashMap::new()).unwrap();
        let event_log = services.iter().find(|s| s.name == "EventLog").unwrap();
        assert_eq!(event_log.startup_type, ServiceStartType::Automatic);
        assert!(!event_log.account.is_empty());
        assert_ne!(event_log.service_type, 0);
    }

    #[test]
    fn the_machine_has_services_and_each_is_described_once() {
        let scm = Scm::new();
        let connection = scm.connection().expect("anyone may enumerate services");
        let mut configs = HashMap::new();
        let services = scan(connection.handle(), &mut Vec::new(), &mut configs).expect("listed");
        assert!(!services.is_empty());
        assert_eq!(configs.len(), services.len());
        assert!(services.iter().any(|s| s.state == ServiceState::Running && s.pid != 0));
    }

    fn listed(name: &str, pid: u32) -> ServiceStats {
        ServiceStats {
            name: name.to_string(),
            pid,
            ..Default::default()
        }
    }

    #[test]
    fn a_configuration_that_could_not_be_read_is_read_again_next_scan() {
        let scm = Scm::new();
        let connection = scm.connection().unwrap();
        let mut configs = HashMap::new();
        describe(connection.handle(), &mut [listed("UniprocNoSuchService", 0)], &mut configs);
        assert!(!configs.contains_key("UniprocNoSuchService"), "{configs:?}");
    }

    #[test]
    fn a_service_in_another_process_is_read_again() {
        let scm = Scm::new();
        let connection = scm.connection().unwrap();
        let running = scan(connection.handle(), &mut Vec::new(), &mut HashMap::new())
            .expect("listed")
            .into_iter()
            .find(|s| s.name == "EventLog")
            .expect("EventLog is listed");
        let stale = Config {
            image_path: "stale".into(),
            pid: running.pid.wrapping_add(4),
            ..Default::default()
        };
        let mut configs = HashMap::from([("EventLog".to_string(), stale)]);
        let mut services = [listed("EventLog", running.pid)];
        describe(connection.handle(), &mut services, &mut configs);
        assert_eq!(services[0].image_path, running.image_path);
    }

    #[test]
    fn configuration_is_refreshed_even_when_the_pid_did_not_change() {
        let scm = Scm::new();
        let connection = scm.connection().unwrap();
        let actual = config(connection.handle(), "EventLog").unwrap();
        let stale = Config {
            image_path: "stale".into(),
            read_at: Some(Instant::now() - Duration::from_secs(31)),
            ..Default::default()
        };
        let mut configs = HashMap::from([("EventLog".to_string(), stale)]);
        let mut services = [listed("EventLog", 0)];
        describe(connection.handle(), &mut services, &mut configs);
        assert_eq!(services[0].image_path, actual.image_path);
        assert_eq!(services[0].startup_type, actual.startup_type);
        assert_eq!(services[0].account, actual.account);
    }

    #[test]
    fn services_that_could_not_be_listed_are_no_scan() {
        use crate::bindings::{CloseServiceHandle, OpenSCManagerW, SC_MANAGER_CONNECT};

        let connect_only =
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT as u32) };
        assert!(!connect_only.0.is_null());
        let mut configs = HashMap::new();
        let scanned = scan(ScHandle(connect_only), &mut Vec::new(), &mut configs);
        let _ = unsafe { CloseServiceHandle(connect_only) };
        assert!(scanned.is_none(), "{} services", scanned.unwrap_or_default().len());
    }

    #[test]
    fn the_first_scan_is_in_before_start_returns_and_a_stop_ends_the_thread() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let inventory = Inventory::start(Scm::new(), move |scan| {
            let _ = tx.send(scan.len());
        })
        .unwrap();
        assert!(rx.try_recv().expect("scanned already") > 0);
        let started = std::time::Instant::now();
        drop(inventory);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
