use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{Result, bail};
use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::error;
use tracing::info;
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::core::PWSTR;

use crate::etw::session::session_name_wide;
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

static CONSUMERS: OnceLock<DashMap<u64, Box<dyn Fn(&EVENT_RECORD) + Send + Sync>>> =
    OnceLock::new();

fn consumers() -> &'static DashMap<u64, Box<dyn Fn(&EVENT_RECORD) + Send + Sync>> {
    CONSUMERS.get_or_init(DashMap::new)
}

thread_local! {
    static CURRENT_HANDLE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

unsafe extern "system" fn dispatch(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let key = CURRENT_HANDLE.get();
    if let Some(cb) = consumers().get(&key) {
        cb(&*record);
    }
}

pub struct TraceConsumer {
    handle: PROCESSTRACE_HANDLE,
}

impl TraceConsumer {
    pub fn open<F>(session_name: &str, callback: F) -> Result<Self>
    where
        F: Fn(&EVENT_RECORD) + Send + Sync + 'static,
    {
        let mut w = session_name_wide(session_name);
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(w.as_mut_ptr()),
            Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            },
            Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(dispatch),
            },
            ..Default::default()
        };

        let handle = unsafe { OpenTraceW(&mut logfile) };
        if handle == PROCESSTRACE_HANDLE::default() {
            bail!("OpenTraceW failed for session '{session_name}'");
        }

        consumers().insert(handle.Value, Box::new(callback));
        Ok(Self { handle })
    }

    pub fn spawn_pump(&self, running: Arc<AtomicBool>) {
        let handle = self.handle;
        std::thread::Builder::new()
            .name("etw-pump".into())
            .spawn(move || {
                CURRENT_HANDLE.set(handle.Value);
                let status = unsafe { ProcessTrace(&[handle], None, None) };
                if running.load(Ordering::SeqCst) {
                    error!("ProcessTrace exited unexpectedly: {status:?}");
                }
            })
            .expect("failed to spawn etw-pump");
    }
}

impl Drop for TraceConsumer {
    fn drop(&mut self) {
        consumers().remove(&self.handle.Value);
        let _ = unsafe { CloseTrace(self.handle) };
    }
}
