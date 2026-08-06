use std::mem::size_of;

use anyhow::{Result, bail};
use tracing::{info, warn};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::core::{GUID, PCWSTR};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    Normal,
    SystemLogger,
}

pub struct EtwSession {
    name: String,
    handle: CONTROLTRACE_HANDLE,
}

unsafe impl Send for EtwSession {}
unsafe impl Sync for EtwSession {}

impl EtwSession {
    pub fn start(name: &str, flags: u32, mode: SessionMode) -> Result<Self> {
        let w = session_name_wide(name);
        let handle = start_raw(w.as_ptr(), None, flags, mode)?;
        Ok(Self {
            name: name.to_string(),
            handle,
        })
    }

    pub fn handle(&self) -> CONTROLTRACE_HANDLE {
        self.handle
    }

    pub fn enable(&self, guid: &GUID) -> Result<()> {
        enable_provider(self.handle, guid)
    }

    pub fn enable_soft(&self, guid: &GUID, label: &str) {
        if let Err(e) = self.enable(guid) {
            warn!("enable {label}: {e:#}");
        }
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        let w = session_name_wide(&self.name);
        let name_ptr = PCWSTR(w.as_ptr());
        let props_size = size_of::<EVENT_TRACE_PROPERTIES>() + w.len() * 2 + 512;
        let mut buf = vec![0u8; props_size];
        let props = unsafe { build_props(&mut buf, None, 0, SessionMode::Normal) };
        let _ = unsafe { StopTraceW(self.handle, name_ptr, props) };
        info!("ETW session '{}' stopped", self.name);
    }
}

pub fn session_name_wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

fn start_raw(
    name_ptr: *const u16,
    guid: Option<GUID>,
    flags: u32,
    mode: SessionMode,
) -> Result<CONTROLTRACE_HANDLE> {
    let pcwstr = PCWSTR(name_ptr);
    let displayed = String::from_utf16_lossy(unsafe { pcwstr.as_wide() });
    let name_bytes = unsafe { pcwstr.as_wide() }.len() * 2;
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + 2;
    let mut buf = vec![0u8; props_size];
    let props = unsafe { build_props(&mut buf, guid, flags, mode) };

    let mut handle = CONTROLTRACE_HANDLE::default();
    let status = unsafe { StartTraceW(&mut handle, pcwstr, props) };

    if status == ERROR_SUCCESS {
        info!(
            "ETW session '{displayed}' started (handle={})",
            handle.Value
        );
    } else if status == ERROR_ALREADY_EXISTS {
        warn!("Session '{displayed}' already exists, restarting...");
        let _ = unsafe { StopTraceW(handle, pcwstr, props) };
        let status2 = unsafe { StartTraceW(&mut handle, pcwstr, props) };
        if status2 != ERROR_SUCCESS {
            bail!("StartTraceW after restart '{displayed}': {status2:?}");
        }
        info!(
            "ETW session '{displayed}' restarted (handle={})",
            handle.Value
        );
    } else {
        bail!("StartTraceW '{displayed}': {status:?}");
    }

    Ok(handle)
}

unsafe fn build_props(
    buf: &mut Vec<u8>,
    guid: Option<GUID>,
    flags: u32,
    mode: SessionMode,
) -> &mut EVENT_TRACE_PROPERTIES {
    let props = &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
    props.Wnode.BufferSize = buf.len() as u32;
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.Wnode.ClientContext = 1; // QPC timestamps
    if let Some(g) = guid {
        props.Wnode.Guid = g;
    }
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    if mode == SessionMode::SystemLogger {
        props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
    }
    props.BufferSize = crate::etw::vars::BUFFER_SIZE_KB;
    props.MinimumBuffers = crate::etw::vars::MINIMUM_BUFFERS;
    props.MaximumBuffers = crate::etw::vars::MAXIMUM_BUFFERS;
    props.FlushTimer = crate::etw::vars::FLUSH_TIMER_SEC;
    props.EnableFlags = EVENT_TRACE_FLAG(flags);
    props
}

fn enable_provider(handle: CONTROLTRACE_HANDLE, guid: &GUID) -> Result<()> {
    let params = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        ..Default::default()
    };
    let err = unsafe {
        EnableTraceEx2(
            handle,
            guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            0xFFFF_FFFF_FFFF_FFFF,
            0,
            0,
            Some(&params),
        )
    };
    if err != ERROR_SUCCESS {
        bail!("EnableTraceEx2({guid:?}): {err:?}");
    }
    Ok(())
}
