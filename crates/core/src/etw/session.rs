use std::mem::size_of;

use anyhow::{Result, bail};
use tracing::{info, warn};
use windows::Win32::{
    CONTROLTRACE_ID, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    EVENT_TRACE_SYSTEM_LOGGER_MODE, EnableTraceEx2, StartTraceW, StopTraceW,
    TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR};

use crate::aligned::AlignedBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    Normal,
    SystemLogger,
}

pub struct EtwSession {
    name: String,
    handle: CONTROLTRACE_ID,
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

    pub fn enable(&self, guid: &GUID) -> Result<()> {
        enable_provider(self.handle, guid)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// What ETW says about the session now; None when ETW no longer has it.
    pub fn query(&self) -> Option<SessionCounters> {
        let size = size_of::<EVENT_TRACE_PROPERTIES>() + 2048;
        let mut buf = AlignedBuf::zeroed(size);
        let props = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        props.Wnode.BufferSize = size as u32;
        props.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        props.LogFileNameOffset = (size_of::<EVENT_TRACE_PROPERTIES>() + 1024) as u32;
        let status = unsafe {
            ControlTraceW(self.handle, PCWSTR::null(), props, EVENT_TRACE_CONTROL_QUERY as u32)
        };
        (status == ERROR_SUCCESS as u32).then(|| SessionCounters {
            events_lost: props.EventsLost,
            realtime_buffers_lost: props.RealTimeBuffersLost,
            log_buffers_lost: props.LogBuffersLost,
            buffers_written: props.BuffersWritten,
            buffers: props.NumberOfBuffers,
            free_buffers: props.FreeBuffers,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCounters {
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
    pub log_buffers_lost: u32,
    pub buffers_written: u32,
    pub buffers: u32,
    pub free_buffers: u32,
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        let w = session_name_wide(&self.name);
        let name_ptr = PCWSTR(w.as_ptr());
        let props_size = size_of::<EVENT_TRACE_PROPERTIES>() + w.len() * 2 + 512;
        let mut buf = AlignedBuf::zeroed(props_size);
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
) -> Result<CONTROLTRACE_ID> {
    let pcwstr = PCWSTR(name_ptr);
    let displayed = String::from_utf16_lossy(unsafe { pcwstr.as_wide() });
    let name_bytes = unsafe { pcwstr.as_wide() }.len() * 2;
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + 2;
    let mut buf = AlignedBuf::zeroed(props_size);
    let props = unsafe { build_props(&mut buf, guid, flags, mode) };

    let mut handle = CONTROLTRACE_ID::default();
    let status = unsafe { StartTraceW(&mut handle, pcwstr, props) };

    if status == ERROR_SUCCESS as u32 {
        info!("ETW session '{displayed}' started (handle={})", handle.0);
    } else if status == ERROR_ALREADY_EXISTS as u32 {
        warn!("Session '{displayed}' already exists, restarting...");
        let mut stop_buf = AlignedBuf::zeroed(props_size + 512);
        let stop_props = unsafe { build_props(&mut stop_buf, None, 0, SessionMode::Normal) };
        let _ = unsafe { StopTraceW(CONTROLTRACE_ID::default(), pcwstr, stop_props) };
        let props = unsafe { build_props(&mut buf, guid, flags, mode) };
        let status2 = unsafe { StartTraceW(&mut handle, pcwstr, props) };
        if status2 != ERROR_SUCCESS as u32 {
            bail!("StartTraceW after restart '{displayed}': {status2:?}");
        }
        info!("ETW session '{displayed}' restarted (handle={})", handle.0);
    } else {
        bail!("StartTraceW '{displayed}': {status:?}");
    }

    Ok(handle)
}

unsafe fn build_props(
    buf: &mut AlignedBuf,
    guid: Option<GUID>,
    flags: u32,
    mode: SessionMode,
) -> &mut EVENT_TRACE_PROPERTIES {
    let props = &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
    props.Wnode.BufferSize = buf.len() as u32;
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID as u32;
    props.Wnode.ClientContext = 1; // QPC timestamps
    if let Some(g) = guid {
        props.Wnode.Guid = g;
    }
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE as u32;
    if mode == SessionMode::SystemLogger {
        props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE as u32;
    }
    props.BufferSize = crate::etw::vars::BUFFER_SIZE_KB;
    props.MinimumBuffers = crate::etw::vars::MINIMUM_BUFFERS;
    props.MaximumBuffers = crate::etw::vars::MAXIMUM_BUFFERS;
    props.FlushTimer = crate::etw::vars::FLUSH_TIMER_SEC;
    props.EnableFlags = flags;
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::{
        EVENT_TRACE_FLAG_DISK_IO, EVENT_TRACE_FLAG_NETWORK_TCPIP, EVENT_TRACE_FLAG_PROFILE,
    };

    fn enabled_flags(name: &str) -> u32 {
        let w = session_name_wide(name);
        let size = size_of::<EVENT_TRACE_PROPERTIES>() + 2048;
        let mut buf = AlignedBuf::zeroed(size);
        let props = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        props.Wnode.BufferSize = size as u32;
        props.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        props.LogFileNameOffset = (size_of::<EVENT_TRACE_PROPERTIES>() + 1024) as u32;
        let status = unsafe {
            ControlTraceW(
                CONTROLTRACE_ID::default(),
                PCWSTR(w.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_QUERY as u32,
            )
        };
        assert_eq!(status, ERROR_SUCCESS as u32, "query '{name}'");
        props.EnableFlags
    }

    fn stop(name: &str) {
        let w = session_name_wide(name);
        let size = size_of::<EVENT_TRACE_PROPERTIES>() + 2048;
        let mut buf = AlignedBuf::zeroed(size);
        let props = unsafe { build_props(&mut buf, None, 0, SessionMode::Normal) };
        let _ = unsafe { StopTraceW(CONTROLTRACE_ID::default(), PCWSTR(w.as_ptr()), props) };
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_leftover_session_is_restarted_with_its_flags() {
        crate::privileges::enable(windows::core::w!("SeSystemProfilePrivilege")).unwrap();
        let flags = (EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_NETWORK_TCPIP) as u32;
        let name = "Uniproc-RestartTest";
        stop(name);
        let w = session_name_wide(name);

        start_raw(w.as_ptr(), None, flags, SessionMode::SystemLogger).unwrap();
        assert_eq!(enabled_flags(name), flags);

        start_raw(w.as_ptr(), None, flags, SessionMode::SystemLogger).unwrap();
        let after_restart = enabled_flags(name);
        stop(name);
        assert_eq!(after_restart, flags, "the restarted session lost its kernel flags");
    }
}

fn enable_provider(handle: CONTROLTRACE_ID, guid: &GUID) -> Result<()> {
    let params = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2 as u32,
        ..Default::default()
    };
    let err = unsafe {
        EnableTraceEx2(
            handle,
            guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER as u32,
            TRACE_LEVEL_INFORMATION as u8,
            0xFFFF_FFFF_FFFF_FFFF,
            0,
            0,
            Some(&params),
        )
    };
    if err != ERROR_SUCCESS as u32 {
        bail!("EnableTraceEx2({guid:?}): {err:?}");
    }
    Ok(())
}
