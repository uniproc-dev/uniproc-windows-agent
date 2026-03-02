use std::cell::RefCell;
use std::io::Cursor;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{bail, Result};
use binrw::BinRead;
use parking_lot::Mutex;
use tracing::{error, info, warn};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::*;
use lazy_static::lazy_static;
use windows::Win32::Security::SID;
use crate::etw::signatures::defines::ProcessV4TypeGroup1;
use super::provider::{event_record_callback, ProcessEvent, ProcessEventType, KERNEL_PROCESS_PROVIDER};

const SYSTEM_TRACE_CONTROL_GUID: GUID = GUID::from_values(
    0x9e814aad, 0x3204, 0x11d2,
    [0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39],
);

const KERNEL_PROCESS_PROVIDER_CLASSIC: GUID = GUID::from_values(
    0x3D6FA8D0, 0xFE05, 0x11D0,
    [0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C],
);

const BOOTSTRAP_SESSION: &str = "Uniproc kernel logger session";


pub struct EtwSession {
    name:           String,
    running:        Arc<AtomicBool>,
    session_handle: Mutex<CONTROLTRACE_HANDLE>,
    trace_handle:   Mutex<PROCESSTRACE_HANDLE>,
}

unsafe impl Send for EtwSession {}
unsafe impl Sync for EtwSession {}

impl EtwSession {
    pub fn new(name: &str) -> Self {
        Self {
            name:           name.to_string(),
            running:        Arc::new(AtomicBool::new(false)),
            session_handle: Mutex::new(CONTROLTRACE_HANDLE::default()),
            trace_handle:   Mutex::new(PROCESSTRACE_HANDLE::default()),
        }
    }

    pub fn start_monitoring(&self) -> Result<Vec<ProcessEvent>> {
        let existing = bootstrap_existing_processes()
            .unwrap_or_else(|e| {
                warn!("Bootstrap failed, starting without snapshot: {e:#}");
                Vec::new()
            });

        info!("Bootstrap: got {} existing processes", existing.len());

        self.running.store(true, Ordering::SeqCst);

        let session_handle = start_etw_session(&self.name)?;
        *self.session_handle.lock() = session_handle;

        let trace_handle = open_trace_consumer(&self.name)?;
        *self.trace_handle.lock() = trace_handle;

        spawn_trace_pump(trace_handle, Arc::clone(&self.running));
        enable_kernel_process_provider(session_handle)?;

        info!("Main ETW session started");
        Ok(existing)
    }

    pub fn stop_monitoring(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }

        info!("Stopping ETW monitoring...");

        log_err(close_trace_consumer(*self.trace_handle.lock()),              "CloseTrace");
        log_err(disable_kernel_process_provider(*self.session_handle.lock()), "DisableProvider");
        log_err(stop_etw_session(&self.name, *self.session_handle.lock()),    "StopTraceW");

        info!("ETW session stopped.");
    }
}

pub fn bootstrap_existing_processes() -> Result<Vec<ProcessEvent>> {
    let results: Arc<Mutex<Vec<ProcessEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));

    let results_cb = Arc::clone(&results);
    let done_cb    = Arc::clone(&done);

    let name = session_name_wide(BOOTSTRAP_SESSION);

    let session_handle = start_etw_session_flagged(
        name.as_ptr(),
        None,
        EVENT_TRACE_FLAG_PROCESS.0,
        SessionType::SystemLogger
    )?;

    let trace_handle = open_trace_consumer_with_callback(
        BOOTSTRAP_SESSION,
        move |record| {

            if record.EventHeader.ProviderId != KERNEL_PROCESS_PROVIDER_CLASSIC {
                return;
            }

            //C:/.../*Win SDK*/um/winmeta.h
            const DCStart: u8 = 3;
            match record.EventHeader.EventDescriptor.Opcode {
                DCStart => {

                    let data = unsafe { std::slice::from_raw_parts(
                        record.UserData as *const u8,
                        record.UserDataLength as usize,
                    ) };

                    let mut cursor = Cursor::new(data);

                    let Ok(header) = ProcessV4TypeGroup1::read(&mut cursor) else {
                        warn!("Failed to read process event header");
                        return;
                    };

                    results_cb.lock().push(ProcessEvent {
                        process_id: header.process_id,
                        session_id: header.session_id,
                        image_name: header.image_file_name.to_string(),
                        parent_process_id: header.parent_id,
                        command_line: header.command_line.to_string(),
                        event_type: ProcessEventType::ProcessRundown,
                    });
                }
                _ => {
                    done_cb.store(true, Ordering::SeqCst);
                }
            }
        },
    )?;

    let pump = std::thread::spawn(move || unsafe {
        log_err(check_win32(ProcessTrace(&[trace_handle], None, None), ""), "Bootstrap ProcessTrace");
    });

    let deadline = std::time::Instant::now();
    while !done.load(Ordering::SeqCst) {
        if deadline.elapsed() > Duration::from_secs(30) {
            warn!("Bootstrap rundown timed out after 5s");
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    log_err(close_trace_consumer(trace_handle),                  "Bootstrap CloseTrace");
    log_err(stop_etw_session(BOOTSTRAP_SESSION, session_handle), "Bootstrap StopTrace");
    pump.join().ok();

    Ok(Arc::try_unwrap(results)
        .expect("Arc still held after bootstrap")
        .into_inner())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionType {
    Normal,
    SystemLogger,
}

fn log_err(result: Result<()>, context: &str) {
    if let Err(e) = result {
        error!("{context} failed: {e:?}");
    }
}

fn check_win32(err: WIN32_ERROR, context: &str) -> Result<()> {
    if err == ERROR_SUCCESS { Ok(()) } else { bail!("{context}: {err:?}") }
}

fn session_name_wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn build_trace_properties(
    props_buf:    &mut Vec<u8>,
    guid:         Option<GUID>,
    enable_flags: u32,
    session_type: SessionType,
) -> &mut EVENT_TRACE_PROPERTIES {
    let props = &mut *(props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
    props.Wnode.BufferSize    = props_buf.len() as u32;
    props.Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props.Wnode.ClientContext = 1;
    if let Some(g) = guid { props.Wnode.Guid = g; }

    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    if session_type == SessionType::SystemLogger {
        props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
    }

    props.BufferSize       = 64;
    props.MinimumBuffers   = 4;
    props.MaximumBuffers   = 64;
    props.FlushTimer       = 1;
    props.EnableFlags      = EVENT_TRACE_FLAG(enable_flags);

    props
}


fn start_etw_session(name: &str) -> Result<CONTROLTRACE_HANDLE> {
    let session_name_w = session_name_wide(name);
    start_etw_session_flagged(session_name_w.as_ptr(), None, 0, SessionType::Normal)
}

fn start_etw_session_flagged(
    name:         impl Into<*const u16>,
    guid:         Option<GUID>,
    enable_flags: u32,
    session_type: SessionType,
) -> Result<CONTROLTRACE_HANDLE> {
    let name_ptr       = PCWSTR(name.into());
    let normal_name = String::from_utf16_lossy(unsafe { name_ptr.as_wide() });
    let name_size = unsafe { name_ptr.as_wide() }.len() * 2;
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>() + name_size + 2 /*null-terminator*/;
    let mut props_buf = vec![0u8; props_size];
    let props = unsafe { build_trace_properties(&mut props_buf, guid, enable_flags, session_type) };

    let mut handle = CONTROLTRACE_HANDLE::default();

    let status = unsafe { StartTraceW(&mut handle, name_ptr, props) };

    if status == ERROR_SUCCESS {
        info!("ETW session '{}' started", normal_name);
    } else if status == ERROR_ALREADY_EXISTS {
        warn!("Session '{}' already exists, restarting...", normal_name);
        let _ = unsafe { StopTraceW(handle, name_ptr, props) };
        check_win32(
            unsafe { StartTraceW(&mut handle, name_ptr, props) },
            "StartTraceW after restart",
        )?;
    } else {
        bail!("StartTraceW failed: {status:?}");
    }

    info!(handle = handle.Value, "c");
    Ok(handle)
}

fn stop_etw_session(name: &str, session_handle: CONTROLTRACE_HANDLE) -> Result<()> {
    if session_handle == CONTROLTRACE_HANDLE::default() { return Ok(()); }

    let session_name_w = session_name_wide(name);
    let name_ptr       = PCWSTR(session_name_w.as_ptr());
    let props_size     = size_of::<EVENT_TRACE_PROPERTIES>() + session_name_w.len() * 2 + 512;
    let mut props_buf  = vec![0u8; props_size];
    let props          = unsafe { build_trace_properties(&mut props_buf, None, 0, SessionType::Normal) };

    check_win32(unsafe { StopTraceW(session_handle, name_ptr, props) }, "StopTraceW")
}

fn enable_kernel_process_provider(session_handle: CONTROLTRACE_HANDLE) -> Result<()> {
    let enable_params = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        ..Default::default()
    };
    check_win32(
        unsafe {
            EnableTraceEx2(
                session_handle, &KERNEL_PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                0xFFFF_FFFF_FFFF_FFFF, 0, 0,
                Some(&enable_params),
            )
        },
        "EnableTraceEx2",
    )?;
    info!("Subscribed to Microsoft-Windows-Kernel-Process");
    Ok(())
}

fn disable_kernel_process_provider(session_handle: CONTROLTRACE_HANDLE) -> Result<()> {
    if session_handle == CONTROLTRACE_HANDLE::default() { return Ok(()); }
    check_win32(
        unsafe {
            EnableTraceEx2(
                session_handle, &KERNEL_PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER.0,
                0, 0, 0, 0, None,
            )
        },
        "EnableTraceEx2 (disable)",
    )
}

static BOOTSTRAP_CB: OnceLock<Box<dyn Fn(&EVENT_RECORD) + Send + Sync>> = OnceLock::new();


unsafe extern "system" fn bootstrap_dispatch_callback(event_record: *mut EVENT_RECORD) {

    if event_record.is_null() { return; }
    let record = &*event_record;
    if let Some(cb) = BOOTSTRAP_CB.get() {
        cb(record);
    }
}

fn open_trace_consumer(name: &str) -> Result<PROCESSTRACE_HANDLE> {
    open_trace_consumer_raw(name, event_record_callback)
}

fn open_trace_consumer_with_callback<F>(
    name: &str, callback: F,
) -> Result<PROCESSTRACE_HANDLE>
where
    F: Fn(&EVENT_RECORD) + Send + Sync + 'static,
{
    let _ = BOOTSTRAP_CB.set(Box::new(callback));
    open_trace_consumer_raw(name, bootstrap_dispatch_callback)
}

fn open_trace_consumer_raw(
    name:     &str,
    callback: unsafe extern "system" fn(*mut EVENT_RECORD),
) -> Result<PROCESSTRACE_HANDLE> {
    let mut session_name_w = session_name_wide(name);

    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR(session_name_w.as_mut_ptr()),
        Anonymous1: EVENT_TRACE_LOGFILEW_0 {
            ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        },
        Anonymous2: EVENT_TRACE_LOGFILEW_1 {
            EventRecordCallback: Some(callback),
        },
        ..Default::default()
    };

    let handle = unsafe { OpenTraceW(&mut logfile) };

    if handle == PROCESSTRACE_HANDLE::default() {
        bail!("OpenTraceW failed");
    }
    Ok(handle)
}

fn close_trace_consumer(handle: PROCESSTRACE_HANDLE) -> Result<()> {
    if handle == PROCESSTRACE_HANDLE::default() { return Ok(()); }
    check_win32(unsafe { CloseTrace(handle) }, "CloseTrace")
}

fn spawn_trace_pump(trace_handle: PROCESSTRACE_HANDLE, running: Arc<AtomicBool>) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(()).ok();
        let status = unsafe { ProcessTrace(&[trace_handle], None, None) };
        if running.load(Ordering::SeqCst) {
            error!("ProcessTrace returned unexpectedly: {status:?}");
        } else {
            info!("ProcessTrace finished cleanly.");
        }
    });
    rx.recv().ok();
}