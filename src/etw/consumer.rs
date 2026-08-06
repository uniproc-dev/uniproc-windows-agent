use anyhow::{Result, bail};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::core::PWSTR;

use crate::etw::session::session_name_wide;

pub trait EventSink {
    fn on_event(&mut self, record: &EVENT_RECORD);
}

// One RouterCore shared by several real-time sessions: ProcessTrace accepts
// only one real-time handle per call, so each session gets its own pump
// thread and callbacks serialize on the mutex.
impl<T: EventSink> EventSink for parking_lot::Mutex<T> {
    fn on_event(&mut self, record: &EVENT_RECORD) {
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
    // SAFETY: Context is set in open::<T> to a *mut T of the same T as this
    // monomorphization. The allocation is owned by the pump thread and lives
    // until ProcessTrace returns; ETW callbacks are serialized within one
    // ProcessTrace call, so the &mut does not alias.
    let core = unsafe { &mut *(record.UserContext as *mut T) };
    core.on_event(record);
}

pub struct TraceConsumer {
    handle: PROCESSTRACE_HANDLE,
}

impl TraceConsumer {
    /// # Safety
    /// `ctx` must point to a live `T` that outlives this consumer (until
    /// `CloseTrace` and the end of the corresponding `ProcessTrace` call),
    /// and must not be aliased by another `&mut T` for the same session.
    pub unsafe fn open<T: EventSink>(session_name: &str, ctx: *mut T) -> Result<Self> {
        let mut w = session_name_wide(session_name);
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(w.as_mut_ptr()),
            Context: ctx.cast(),
            Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            },
            Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(dispatch::<T>),
            },
            ..Default::default()
        };

        let handle = unsafe { OpenTraceW(&mut logfile) };
        if handle == PROCESSTRACE_HANDLE::default() {
            bail!("OpenTraceW failed for session '{session_name}'");
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
