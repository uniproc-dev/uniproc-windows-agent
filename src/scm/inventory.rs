use std::collections::HashMap;
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::{RecvTimeoutError, Sender};
use windows::Win32::{
    ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfig2W, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_DESCRIPTIONW, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::core::PCWSTR;

use crate::api::ServiceStats;
use crate::scm::{ScHandle, Scm, Service, state};

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
            if let Ok(connection) = scm.connection() {
                publish(scan(connection.handle(), &mut buf, &mut configs));
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
}

/// Configuration never changes while a service exists, so it is read once per name.
fn scan(scm: ScHandle, buf: &mut Vec<u64>, configs: &mut HashMap<String, Config>) -> Vec<ServiceStats> {
    let mut services = enumerate(scm, buf);
    for service in &mut services {
        let config = configs
            .entry(service.name.clone())
            .or_insert_with(|| config(scm, &service.name));
        service.load_group = config.load_group.clone();
        service.description = config.description.clone();
        service.image_path = config.image_path.clone();
    }
    configs.retain(|name, _| services.iter().any(|s| &s.name == name));
    services
}

fn aligned_bytes(len: u32) -> Vec<u64> {
    vec![0u64; (len.div_ceil(8) as usize).max(1)]
}

unsafe fn as_byte_slice(buf: &mut [u64], len: u32) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, len as usize) }
}

fn config(scm: ScHandle, name: &str) -> Config {
    let mut out = Config::default();
    let Ok(service) = Service::open(scm, name, SERVICE_QUERY_CONFIG) else {
        return out;
    };

    unsafe {
        let mut size = 0u32;
        let _ = QueryServiceConfigW(service.0, None, 0, &mut size);
        if size > 0 {
            let mut storage = aligned_bytes(size);
            let config = storage.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
            if QueryServiceConfigW(service.0, Some(config), size, &mut size).as_bool() {
                out.load_group = (*config).lpLoadOrderGroup.to_string().unwrap_or_default();
                out.image_path = (*config).lpBinaryPathName.to_string().unwrap_or_default();
            }
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

    out
}

/// Every Win32 service with its current state; `buf` keeps its capacity across calls.
fn enumerate(scm: ScHandle, buf: &mut Vec<u64>) -> Vec<ServiceStats> {
    unsafe {
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume = 0u32;

        let _ = EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 as u32,
            SERVICE_STATE_ALL as u32,
            None,
            0,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume),
            PCWSTR::null(),
        );

        if bytes_needed == 0 {
            return Vec::new();
        }

        buf.clear();
        buf.resize(bytes_needed.div_ceil(8) as usize, 0);
        resume = 0;
        let size = bytes_needed;
        if !EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 as u32,
            SERVICE_STATE_ALL as u32,
            Some(as_byte_slice(buf, size).as_mut_ptr()),
            size,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume),
            PCWSTR::null(),
        )
        .as_bool()
        {
            return Vec::new();
        }

        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );
        entries
            .iter()
            .map(|e| ServiceStats {
                name: e.lpServiceName.to_string().unwrap_or_default(),
                display_name: e.lpDisplayName.to_string().unwrap_or_default(),
                pid: e.ServiceStatusProcess.dwProcessId,
                state: state(e.ServiceStatusProcess.dwCurrentState),
                ..Default::default()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServiceState;

    #[test]
    fn the_machine_has_services_and_each_is_described_once() {
        let scm = Scm::new();
        let connection = scm.connection().expect("anyone may enumerate services");
        let mut configs = HashMap::new();
        let services = scan(connection.handle(), &mut Vec::new(), &mut configs);
        assert!(!services.is_empty());
        assert_eq!(configs.len(), services.len());
        assert!(services.iter().any(|s| s.state == ServiceState::Running && s.pid != 0));
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
