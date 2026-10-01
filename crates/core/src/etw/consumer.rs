use anyhow::{Result, bail};
use windows::Win32::{
    CloseTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_LOGFILEW_0, EVENT_TRACE_LOGFILEW_1,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
};
use windows::core::PWSTR;

use crate::etw::session::session_name_wide;

/// What takes the events of one or more sessions, each pumped on a thread
/// of its own, so it is shared between them.
pub trait EventSink: Sync {
    fn on_event(&self, record: &EVENT_RECORD);
}

/// What takes events one at a time.
pub trait Events: Send {
    fn on_event(&mut self, record: &EVENT_RECORD);
}

impl<T: Events> EventSink for parking_lot::Mutex<T> {
    fn on_event(&self, record: &EVENT_RECORD) {
        self.lock().on_event(record);
    }
}

unsafe extern "system" fn dispatch<T: EventSink>(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = unsafe { &*record };
    if record.UserContext.is_null() {
        return;
    }
    // SAFETY: Context is set in open::<T> to a *const T of the same T as
    // this monomorphization, which outlives every ProcessTrace that calls
    // back with it; T is Sync, so the pumps may share it.
    let sink = unsafe { &*(record.UserContext as *const T) };
    sink.on_event(record);
}

pub struct TraceConsumer {
    handle: PROCESSTRACE_HANDLE,
}

impl TraceConsumer {
    /// # Safety
    /// `ctx` must point to a live `T` that outlives this consumer: until
    /// `CloseTrace` and the end of the corresponding `ProcessTrace` call.
    pub unsafe fn open<T: EventSink>(session_name: &str, ctx: *const T) -> Result<Self> {
        let mut w = session_name_wide(session_name);
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(w.as_mut_ptr()),
            Context: ctx.cast_mut().cast(),
            Anonymous: EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: (PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD) as u32,
            },
            Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(dispatch::<T>),
            },
            ..Default::default()
        };

        let handle = unsafe { OpenTraceW(&mut logfile) };
        if handle == PROCESSTRACE_HANDLE::default() || handle.0 == u64::MAX {
            let error = std::io::Error::last_os_error();
            bail!("OpenTraceW failed for session '{session_name}': {error}");
        }

        Ok(Self { handle })
    }

    pub fn handle(&self) -> PROCESSTRACE_HANDLE {
        self.handle
    }
}

impl Drop for TraceConsumer {
    fn drop(&mut self) {
        let _ = unsafe { CloseTrace(self.handle) };
    }
}
