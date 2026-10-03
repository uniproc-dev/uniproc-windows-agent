use std::mem::size_of;

use anyhow::{Result, bail};
use tracing::{info, warn};
use windows::Win32::{
    CONTROLTRACE_ID, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    ERROR_ALREADY_EXISTS, ERROR_MORE_DATA, ERROR_SUCCESS, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_UPDATE, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    EVENT_TRACE_SYSTEM_LOGGER_MODE, EnableTraceEx2, QueryAllTracesW, StartTraceW, StopTraceW,
    WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR};

use crate::aligned::AlignedBuf;
use crate::etw::router::Enable;

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

    pub fn enable(&self, guid: &GUID, enable: Enable) -> Result<()> {
        enable_provider(self.handle, guid, enable)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// What ETW says about the session of this name now; None when ETW no
    /// longer has one. Asked by name: a logger id ETW freed may since name
    /// someone else's session.
    pub fn query(&self) -> Option<SessionCounters> {
        let mut buf = control(&self.name, EVENT_TRACE_CONTROL_QUERY as u32, None)?;
        let props = unsafe { &*(buf.as_mut_ptr() as *const EVENT_TRACE_PROPERTIES) };
        Some(SessionCounters {
            events_lost: props.EventsLost,
            realtime_buffers_lost: props.RealTimeBuffersLost,
            log_buffers_lost: props.LogBuffersLost,
            buffers_written: props.BuffersWritten,
            buffers: props.NumberOfBuffers,
            free_buffers: props.FreeBuffers,
        })
    }

    /// Sets how many milliseconds ETW holds a buffer that is not full yet.
    /// Everything else the session was started with stays.
    pub fn set_flush_timer(&self, ms: u32) -> Result<()> {
        let Some(mut current) = control(&self.name, EVENT_TRACE_CONTROL_QUERY as u32, None) else {
            bail!("ETW session '{}' is gone", self.name);
        };
        let props = unsafe { &mut *(current.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        props.FlushTimer = ms;
        if control(&self.name, EVENT_TRACE_CONTROL_UPDATE as u32, Some(current)).is_none() {
            bail!("ETW session '{}' kept its flush timer", self.name);
        }
        Ok(())
    }
}

/// Runs `code` on the session of this name with `props`, or with blank
/// ones, and answers what ETW wrote back; None when ETW refused.
fn control(name: &str, code: u32, props: Option<AlignedBuf>) -> Option<AlignedBuf> {
    let size = size_of::<EVENT_TRACE_PROPERTIES>() + 2048;
    let mut buf = props.unwrap_or_else(|| AlignedBuf::zeroed(size));
    let props = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    props.Wnode.BufferSize = buf.len() as u32;
    props.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    props.LogFileNameOffset = (size_of::<EVENT_TRACE_PROPERTIES>() + 1024) as u32;
    let name = session_name_wide(name);
    let status = unsafe { ControlTraceW(CONTROLTRACE_ID::default(), PCWSTR(name.as_ptr()), props, code) };
    (status == ERROR_SUCCESS as u32).then_some(buf)
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
        stop(&self.name);
        info!("ETW session '{}' stopped", self.name);
    }
}

pub fn session_name_wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Stops the session of this name; true when ETW had one.
pub fn stop(name: &str) -> bool {
    let w = session_name_wide(name);
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>() + w.len() * 2 + 512;
    let mut buf = AlignedBuf::zeroed(props_size);
    let props = unsafe { build_props(&mut buf, None, 0, SessionMode::Normal) };
    unsafe { StopTraceW(CONTROLTRACE_ID::default(), PCWSTR(w.as_ptr()), props) == ERROR_SUCCESS as u32 }
}

/// The names of the trace sessions running now, as many as ETW lists.
pub fn running() -> Vec<String> {
    const MOST: usize = 64;
    const NAME_BYTES: usize = 1024;
    let stride = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * NAME_BYTES;
    let mut buf = AlignedBuf::zeroed(stride * MOST);
    let base = buf.as_mut_ptr();
    let mut all: Vec<*mut EVENT_TRACE_PROPERTIES> = (0..MOST)
        .map(|i| unsafe {
            let props = base.add(i * stride).cast::<EVENT_TRACE_PROPERTIES>();
            (*props).Wnode.BufferSize = stride as u32;
            (*props).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*props).LogFileNameOffset = (size_of::<EVENT_TRACE_PROPERTIES>() + NAME_BYTES) as u32;
            props
        })
        .collect();
    let mut listed = 0u32;
    let status = unsafe { QueryAllTracesW(all.as_mut_ptr(), MOST as u32, &mut listed) };
    if status != ERROR_SUCCESS as u32 && status != ERROR_MORE_DATA as u32 {
        return Vec::new();
    }
    all[..(listed as usize).min(MOST)]
        .iter()
        .filter_map(|&props| unsafe {
            let name = props.cast::<u8>().add((*props).LoggerNameOffset as usize).cast::<u16>();
            PCWSTR(name).to_string().ok()
        })
        .collect()
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
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE as u32 | crate::etw::vars::EVENT_TRACE_USE_MS_FLUSH_TIMER;
    if mode == SessionMode::SystemLogger {
        props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE as u32;
    }
    props.BufferSize = crate::etw::vars::BUFFER_SIZE_KB;
    props.MinimumBuffers = crate::etw::vars::MINIMUM_BUFFERS;
    props.MaximumBuffers = crate::etw::vars::MAXIMUM_BUFFERS;
    props.FlushTimer = crate::etw::vars::FLUSH_TIMER_MS;
    props.EnableFlags = flags;
    props
}

fn enable_provider(handle: CONTROLTRACE_ID, guid: &GUID, enable: Enable) -> Result<()> {
    let params = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2 as u32,
        ..Default::default()
    };
    let err = unsafe {
        EnableTraceEx2(
            handle,
            guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER as u32,
            enable.level,
            enable.keywords,
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::{
        EVENT_TRACE_FLAG_DISK_IO, EVENT_TRACE_FLAG_NETWORK_TCPIP, EVENT_TRACE_FLAG_PROFILE,
    };

    fn queried(name: &str) -> EVENT_TRACE_PROPERTIES {
        let mut buf = control(name, EVENT_TRACE_CONTROL_QUERY as u32, None).unwrap_or_else(|| panic!("query '{name}'"));
        unsafe { *(buf.as_mut_ptr() as *const EVENT_TRACE_PROPERTIES) }
    }

    fn enabled_flags(name: &str) -> u32 {
        queried(name).EnableFlags
    }

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn the_flush_timer_changes_and_the_kernel_flags_stay() {
        crate::privileges::enable(windows::core::w!("SeSystemProfilePrivilege")).unwrap();
        let flags = (EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_NETWORK_TCPIP) as u32;
        let name = "Uniproc-FlushTest";
        stop(name);
        let session = EtwSession::start(name, flags, SessionMode::SystemLogger).unwrap();
        assert_eq!(queried(name).FlushTimer, crate::etw::vars::FLUSH_TIMER_MS);
        session.set_flush_timer(1000).unwrap();
        let after = queried(name);
        drop(session);
        assert_eq!(after.FlushTimer, 1000);
        assert_eq!(after.EnableFlags, flags, "the update cleared the kernel flags");
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

    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn a_running_session_is_listed_and_stopped_by_name() {
        let name = "Uniproc-ListTest";
        stop(name);
        let session = EtwSession::start(name, 0, SessionMode::Normal).unwrap();
        assert!(running().iter().any(|n| n == name), "{:?}", running());
        assert!(stop(name));
        assert!(!running().iter().any(|n| n == name));
        assert!(!stop(name), "nothing left to stop");
        drop(session);
    }
}
