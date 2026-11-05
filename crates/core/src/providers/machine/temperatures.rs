use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use crossbeam_channel::{Receiver, Sender};
use libloading::Library;
use parking_lot::Mutex;

use crate::sample::{MachineTemperatures, TemperatureStatus};

const PERIOD: Duration = Duration::from_secs(1);
const STALE_AFTER: Duration = Duration::from_secs(5);
const MAX_JSON: usize = 8 << 20;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
static ACTIVE: AtomicBool = AtomicBool::new(false);

struct WorkerClaim(&'static AtomicBool);

impl Drop for WorkerClaim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct Shared {
    wanted: AtomicBool,
    stopped: AtomicBool,
    latest: Mutex<(Instant, Arc<MachineTemperatures>)>,
}

pub struct Temperatures {
    shared: Arc<Shared>,
    wake: Sender<()>,
    inbox: Receiver<()>,
    worker: Option<(JoinHandle<()>, Receiver<()>)>,
}

impl Default for Temperatures {
    fn default() -> Self {
        let (wake, inbox) = crossbeam_channel::bounded(1);
        Self {
            shared: Arc::new(Shared {
                wanted: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                latest: Mutex::new((
                    Instant::now(),
                    Arc::new(unavailable("temperature backend has not been sampled")),
                )),
            }),
            wake,
            inbox,
            worker: None,
        }
    }
}

impl Temperatures {
    pub fn demand(&mut self, wanted: bool) {
        if self.shared.wanted.swap(wanted, Ordering::SeqCst) == wanted
            && (!wanted || self.worker.is_some())
        {
            return;
        }
        if wanted && self.worker.is_none() {
            self.start(&ACTIVE, work);
            return;
        }
        let _ = self.wake.try_send(());
    }

    fn start(
        &mut self,
        active: &'static AtomicBool,
        run: impl FnOnce(Arc<Shared>, Receiver<()>) + Send + 'static,
    ) {
        if active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            publish(
                &self.shared,
                failed("previous temperature worker is still active".into()),
            );
            return;
        }
        let claim = WorkerClaim(active);
        let shared = self.shared.clone();
        let inbox = self.inbox.clone();
        let (done, completion) = crossbeam_channel::bounded(1);
        match std::thread::Builder::new()
            .name("temperatures".into())
            .spawn(move || {
                run(shared, inbox);
                drop(claim);
                let _ = done.send(());
            }) {
            Ok(worker) => self.worker = Some((worker, completion)),
            Err(error) => publish(&self.shared, failed(error.to_string())),
        }
    }

    pub fn latest(&self) -> Arc<MachineTemperatures> {
        let (at, sample) = &*self.shared.latest.lock();
        if at.elapsed() > STALE_AFTER {
            Arc::new(failed(
                "temperature backend did not complete a sample within five seconds".into(),
            ))
        } else {
            sample.clone()
        }
    }
}

impl Drop for Temperatures {
    fn drop(&mut self) {
        self.shared.stopped.store(true, Ordering::SeqCst);
        let _ = self.wake.try_send(());
        if let Some((worker, completion)) = self.worker.take() {
            if completion.recv_timeout(SHUTDOWN_TIMEOUT).is_ok() || worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

fn unavailable(error: &str) -> MachineTemperatures {
    MachineTemperatures {
        status: TemperatureStatus::Unavailable,
        error: error.into(),
        devices: Vec::new(),
    }
}

fn failed(error: String) -> MachineTemperatures {
    MachineTemperatures {
        status: TemperatureStatus::Error,
        error,
        devices: Vec::new(),
    }
}

fn publish(shared: &Shared, sample: MachineTemperatures) {
    *shared.latest.lock() = (Instant::now(), Arc::new(sample));
}

fn work(shared: Arc<Shared>, inbox: Receiver<()>) {
    let mut backend = None;
    while !shared.stopped.load(Ordering::SeqCst) {
        if !shared.wanted.load(Ordering::SeqCst) {
            backend = None;
            if inbox.recv().is_err() {
                return;
            }
            continue;
        }
        if backend.is_none() {
            match Bridge::load() {
                Ok(bridge) => backend = Some(bridge),
                Err(error) => publish(&shared, unavailable(&format!("{error:#}"))),
            }
        }
        if let Some(bridge) = &mut backend {
            let sample = bridge
                .sample()
                .unwrap_or_else(|error| failed(format!("{error:#}")));
            publish(&shared, sample);
            if !bridge.opened {
                backend = None;
            }
        }
        let _ = inbox.recv_timeout(PERIOD);
    }
}

type Call = unsafe extern "C" fn() -> i32;
type Read = unsafe extern "C" fn(*mut u8, i32) -> i32;

struct Bridge {
    update: Call,
    read: Read,
    close: unsafe extern "C" fn(),
    opened: bool,
}

impl Bridge {
    fn load() -> Result<Self> {
        let library = library()?;
        unsafe {
            let version = library.get::<unsafe extern "C" fn() -> u32>(b"lhm_abi_version\0")?;
            ensure!(version() == 1, "unsupported LHM ABI version");
            let open = *library.get::<Call>(b"lhm_open\0")?;
            let update = *library.get::<Call>(b"lhm_update\0")?;
            let read = *library.get::<Read>(b"lhm_read\0")?;
            let close = *library.get::<unsafe extern "C" fn()>(b"lhm_close\0")?;
            let opened = open() == 0;
            Ok(Self {
                update,
                read,
                close,
                opened,
            })
        }
    }

    fn sample(&mut self) -> Result<MachineTemperatures> {
        let updated = self.opened && unsafe { (self.update)() } == 0;
        let bytes = read_cached(|buffer, cap| unsafe { (self.read)(buffer, cap) })?;
        let sample = decode(&bytes)?;
        ensure!(
            updated || sample.status != TemperatureStatus::Available,
            "LHM failed but returned an available snapshot"
        );
        Ok(sample)
    }
}

fn library() -> Result<&'static Library> {
    static LIBRARY: Mutex<Option<&'static Library>> = Mutex::new(None);
    let mut cached = LIBRARY.lock();
    if let Some(library) = *cached {
        return Ok(library);
    }
    let path = std::env::current_exe()?.with_file_name("uniproc-lhm.dll");
    let library = load_library(&path)?;
    *cached = Some(library);
    Ok(library)
}

fn load_library(path: &Path) -> Result<&'static Library> {
    let library = unsafe { Library::new(&path) }
        .with_context(|| format!("could not load {}", path.display()))?;
    Ok(Box::leak(Box::new(library)))
}

impl Drop for Bridge {
    fn drop(&mut self) {
        unsafe { (self.close)() };
    }
}

fn read_cached(mut read: impl FnMut(*mut u8, i32) -> i32) -> Result<Vec<u8>> {
    let required = read(std::ptr::null_mut(), 0);
    ensure!(
        required > 0 && required as usize <= MAX_JSON,
        "invalid LHM JSON size: {required}"
    );
    let mut bytes = vec![0; required as usize];
    let written = read(bytes.as_mut_ptr(), required);
    ensure!(
        written == required,
        "LHM cached JSON changed or could not be read"
    );
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<MachineTemperatures> {
    let sample: MachineTemperatures = serde_json::from_slice(bytes)?;
    for sensor in sample.devices.iter().flat_map(|device| &device.sensors) {
        if sensor.celsius.is_some_and(|value| !value.is_finite()) {
            bail!("non-finite temperature for {}", sensor.id);
        }
    }
    Ok(sample)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuck_worker_has_bounded_shutdown_and_keeps_the_process_claim() {
        static CLAIM: AtomicBool = AtomicBool::new(false);
        let wait = Duration::from_secs(10);
        let (entered, started) = crossbeam_channel::bounded(1);
        let (release, blocked) = crossbeam_channel::bounded(1);
        let mut first = Temperatures::default();
        first.start(&CLAIM, move |_, _| {
            entered.send(()).unwrap();
            blocked.recv().unwrap();
        });
        started.recv_timeout(wait).unwrap();
        let completion = first.worker.as_ref().unwrap().1.clone();
        let before = Instant::now();
        drop(first);
        assert!(before.elapsed() >= SHUTDOWN_TIMEOUT);
        assert!(before.elapsed() < SHUTDOWN_TIMEOUT + wait);

        let mut second = Temperatures::default();
        second.start(&CLAIM, |_, _| {
            panic!("a second worker started while the first was stuck")
        });
        assert!(second.worker.is_none());
        assert_eq!(second.latest().status, TemperatureStatus::Error);
        release.send(()).unwrap();
        completion.recv_timeout(wait).unwrap();
        assert!(!CLAIM.load(Ordering::SeqCst));

        let (entered, started) = crossbeam_channel::bounded(1);
        second.start(&CLAIM, move |_, _| entered.send(()).unwrap());
        started.recv_timeout(wait).unwrap();
        drop(second);
        assert!(!CLAIM.load(Ordering::SeqCst));
    }

    #[test]
    fn missing_library_is_unavailable_without_readings() {
        let path = std::env::current_exe().unwrap().join("uniproc-lhm.dll");
        let error = load_library(&path).err().unwrap();
        let sample = unavailable(&format!("{error:#}"));
        assert_eq!(sample.status, TemperatureStatus::Unavailable);
        assert!(!sample.error.is_empty());
        assert!(sample.devices.is_empty());
    }

    #[test]
    fn readings_preserve_hardware_ids_and_missing_values() {
        let sample = decode(br#"{"status":"available","error":"","devices":[{"id":"/gpu-nvidia/0","name":"GPU","category":"gpu","status":"available","error":"","sensors":[{"id":"/gpu-nvidia/0/temperature/2","name":"VRAM","celsius":61.5},{"id":"/gpu-nvidia/0/temperature/3","name":"Hot spot","celsius":null}]}]}"#).unwrap();
        assert_eq!(
            sample.devices[0].sensors[0].id,
            "/gpu-nvidia/0/temperature/2"
        );
        assert_eq!(sample.devices[0].sensors[0].celsius, Some(61.5));
        assert_eq!(sample.devices[0].sensors[1].celsius, None);
    }

    #[test]
    fn invalid_payloads_are_not_readings() {
        assert!(decode(br#"{"status":"available","error":"","devices":[{"id":"x","name":"x","category":"cpu","status":"available","error":"","sensors":[{"id":"x/t","name":"x","celsius":1e999}]}]}"#).is_err());
        assert!(read_cached(|_, _| -1).is_err());
        assert!(read_cached(|_, _| (MAX_JSON + 1) as i32).is_err());
    }

    #[test]
    fn cached_json_is_copied_without_a_second_poll() {
        let json = br#"{"status":"unavailable","error":"driver missing","devices":[]}"#;
        let mut calls = 0;
        let bytes = read_cached(|buffer, capacity| {
            calls += 1;
            if capacity > 0 {
                assert_eq!(capacity as usize, json.len());
                unsafe { std::ptr::copy_nonoverlapping(json.as_ptr(), buffer, json.len()) };
            }
            json.len() as i32
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(
            decode(&bytes).unwrap().status,
            TemperatureStatus::Unavailable
        );
        assert!(read_cached(|buffer, _| if buffer.is_null() { 10 } else { 11 }).is_err());
    }

    #[test]
    fn projection_only_exposes_temperatures_to_requesting_subscribers() {
        use crate::sample::{MachineMetric, MachineSample};
        let sample = MachineSample {
            temperatures: Some(Arc::new(MachineTemperatures::default())),
            ..Default::default()
        };
        assert!(
            sample
                .project(MachineMetric::Cpu.into())
                .temperatures
                .is_none()
        );
        assert!(Arc::ptr_eq(
            sample.temperatures.as_ref().unwrap(),
            sample
                .project(MachineMetric::Temperatures.into())
                .temperatures
                .as_ref()
                .unwrap()
        ));
    }

    #[test]
    fn stale_backend_does_not_return_old_available_values() {
        let reader = Temperatures::default();
        *reader.shared.latest.lock() = (
            Instant::now() - STALE_AFTER - PERIOD,
            Arc::new(MachineTemperatures {
                status: TemperatureStatus::Available,
                ..Default::default()
            }),
        );
        let sample = reader.latest();
        assert_eq!(sample.status, TemperatureStatus::Error);
        assert!(sample.devices.is_empty());
    }
}
