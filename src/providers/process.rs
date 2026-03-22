use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use binrw::BinRead;
use parking_lot::Mutex;
use tracing::warn;

use crate::collector::provider::{ProcessMap, Provider};
use crate::collector::state::{ProcessStarted, StateChange};
use crate::etw::consumer::TraceConsumer;
use crate::etw::kernel_session::KernelSessionRouter;
use crate::etw::session::{EtwSession, SessionMode};
use crate::etw::signatures::defines::{ProcessStartV4Header, ProcessStopData, ThreadTypeGroup1};
use crate::etw::vars::{KERNEL_PROCESS_PROVIDER, PROCESS_TASK_GUID};
use crate::providers::utils::to_user_data;

const SESSION_NAME: &str = "Uniproc-Process";

const EVENT_ID_PROCESS_START: u16 = 1;
const EVENT_ID_PROCESS_STOP: u16 = 2;
const EVENT_ID_THREAD_START: u16 = 3;
const EVENT_ID_THREAD_STOP: u16 = 4;
pub struct KernelProcessProvider {
    queue: Arc<Mutex<Vec<StateChange>>>,
    session: Mutex<Option<EtwSession>>,
    consumer: Mutex<Option<TraceConsumer>>,
    running: Arc<AtomicBool>,
}

impl KernelProcessProvider {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
            session: Mutex::new(None),
            consumer: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Provider for KernelProcessProvider {
    fn start(&self, _: ProcessMap, _: Arc<KernelSessionRouter>) -> Result<()> {
        let session = EtwSession::start(SESSION_NAME, 0, SessionMode::Normal)?;
        session.enable(&KERNEL_PROCESS_PROVIDER)?;

        let queue = Arc::clone(&self.queue);
        let consumer = TraceConsumer::open(SESSION_NAME, move |record| {
            if record.EventHeader.ProviderId != PROCESS_TASK_GUID {
                return;
            }

            let Some(data) = to_user_data(&record) else {
                return;
            };
            let change = match record.EventHeader.EventDescriptor.Id {
                EVENT_ID_PROCESS_START => {
                    let Ok(hdr) = ProcessStartV4Header::read(&mut Cursor::new(data)) else {
                        warn!("Process: failed to parse Start");
                        return;
                    };
                    StateChange::ProcessStarted(ProcessStarted {
                        pid: hdr.process_id,
                        parent_pid: hdr.parent_process_id,
                        session_id: hdr.session_id,
                        image_name: hdr.image_name.to_string(),
                        command_line: String::new(),
                    })
                }
                EVENT_ID_PROCESS_STOP => {
                    let Ok(hdr) = ProcessStopData::read(&mut Cursor::new(data)) else {
                        warn!("Process: failed to parse Stop");
                        return;
                    };
                    StateChange::ProcessStopped(hdr.process_id)
                }
                EVENT_ID_THREAD_START => {
                    let Ok(hdr) = ThreadTypeGroup1::read(&mut Cursor::new(data)) else {
                        warn!("Thread: failed to parse Start");
                        return;
                    };
                    StateChange::ThreadStarted {
                        pid: hdr.process_id,
                        tid: hdr.thread_id,
                    }
                }
                EVENT_ID_THREAD_STOP => {
                    let Ok(hdr) = ThreadTypeGroup1::read(&mut Cursor::new(data)) else {
                        warn!("Thread: failed to parse Stop");
                        return;
                    };
                    StateChange::ThreadStopped { tid: hdr.thread_id }
                }
                _ => return,
            };
            queue.lock().push(change);
        })?;

        self.running.store(true, Ordering::SeqCst);
        consumer.spawn_pump(Arc::clone(&self.running));

        *self.session.lock() = Some(session);
        *self.consumer.lock() = Some(consumer);
        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.consumer.lock().take();
        self.session.lock().take();
    }

    fn drain(&self) -> Vec<StateChange> {
        std::mem::take(&mut *self.queue.lock())
    }
}
