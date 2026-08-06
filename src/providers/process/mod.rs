mod events;
mod vars;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use parking_lot::Mutex;

use crate::etw::router::KernelRouterBuilder;
use crate::etw::signatures::utils::parse;
use crate::providers::process::events::{ProcessStartV4Header, ProcessStopData, ThreadTypeGroup1};
use crate::providers::process::vars::*;
use crate::providers::provider::{LivePids, Provider};
use crate::providers::utils::{parse_cmd_line, query_command_line};
use crate::sink::Sink;
use crate::state::events::{ProcessStarted, StateChange};

pub use vars::KERNEL_PROCESS_PROVIDER;

/// Resolving a command line is OpenProcess + 3x ReadProcessMemory — far too
/// slow for the shared ETW pump thread (part 3 merged this session's pump
/// with disk/network, so blocking here stalls every other route too).
/// The manifest handler only queues the pid; a dedicated worker thread does
/// the actual (blocking) enrichment and emits a follow-up StateChange.
pub struct KernelProcessProvider {
    tx: Sender<u32>,
    rx: Mutex<Option<Receiver<u32>>>,
    running: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl KernelProcessProvider {
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            running: Arc::new(AtomicBool::new(false)),
            worker: Mutex::new(None),
        }
    }
}

impl Default for KernelProcessProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for KernelProcessProvider {
    fn register(&self, b: &mut KernelRouterBuilder) -> Result<()> {
        let tx = self.tx.clone();
        b.manifest(KERNEL_PROCESS_PROVIDER)
            .on(&[KERNEL_PROCESS_PROVIDER], move |record, data| {
                let change = match record.EventHeader.EventDescriptor.Id {
                    EVENT_ID_PROCESS_START => {
                        let hdr = parse::<ProcessStartV4Header>(data)?;
                        // Non-blocking: worst case the channel is full/closed
                        // (provider shutting down) and command_line stays empty.
                        let _ = tx.send(hdr.process_id);

                        StateChange::ProcessStarted(ProcessStarted {
                            pid: hdr.process_id,
                            parent_pid: hdr.parent_process_id,
                            session_id: hdr.session_id,
                            image_name: hdr.image_name.to_string(),
                            package_full_name: hdr.package_full_name.to_string(),
                            package_relative_app_id: hdr.package_relative_app_id.to_string(),
                            command_line: Vec::new(),
                        })
                    }
                    EVENT_ID_PROCESS_STOP => {
                        let hdr = parse::<ProcessStopData>(data)?;
                        StateChange::ProcessStopped(hdr.process_id)
                    }
                    EVENT_ID_THREAD_START => {
                        let hdr = parse::<ThreadTypeGroup1>(data)?;
                        StateChange::ThreadStarted {
                            pid: hdr.process_id,
                            tid: hdr.thread_id,
                        }
                    }
                    EVENT_ID_THREAD_STOP => {
                        let hdr = parse::<ThreadTypeGroup1>(data)?;
                        StateChange::ThreadStopped { tid: hdr.thread_id }
                    }
                    _ => return None,
                };
                Some(change)
            });
        Ok(())
    }

    fn start(&self, _: LivePids, sink: Sink) -> Result<()> {
        let Some(rx) = self.rx.lock().take() else {
            return Ok(());
        };
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        let handle = std::thread::Builder::new()
            .name("process-cmdline".into())
            .spawn(move || {
                // Timeout, not channel-disconnect: the router-held Sender
                // clone only drops when KernelRouter drops, which happens
                // *after* Supervisor::stop() has already called this stop().
                while running.load(Ordering::Relaxed) {
                    match rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(pid) => {
                            let command_line = unsafe { query_command_line(pid) }
                                .map(|s| unsafe { parse_cmd_line(&s) })
                                .unwrap_or_default();
                            sink.emit(StateChange::ProcessCommandLine { pid, command_line });
                        }
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;
        *self.worker.lock() = Some(handle);
        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.worker.lock().take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw::router::KernelRouter;
    use crate::etw::router::tests::ETW_TEST_LOCK;
    use crate::sink::Sink;
    use std::time::{Duration, Instant};

    /// Requires admin and real ETW sessions. Spawns child processes and
    /// expects the manifest route to deliver start/stop events for them.
    /// Run: `cargo test -- --ignored`
    #[test]
    #[ignore = "requires admin and a real ETW session"]
    fn process_events_flow_end_to_end() {
        let _guard = ETW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (sink, rx) = Sink::bounded(1024);
        let mut builder = KernelRouter::builder();
        KernelProcessProvider::new()
            .register(&mut builder)
            .unwrap();
        let router = builder.start(sink).expect("router start");

        let mut child = std::process::Command::new("cmd")
            .args(["/c", "exit", "0"])
            .spawn()
            .expect("spawn child");
        let child_pid = child.id();

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut started = false;
        let mut stopped = false;
        while Instant::now() < deadline && !(started && stopped) {
            for change in rx.try_iter() {
                match change {
                    StateChange::ProcessStarted(e) if e.pid == child_pid => started = true,
                    StateChange::ProcessStopped(pid) if pid == child_pid => stopped = true,
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.wait();
        drop(router);

        assert!(started, "no ProcessStarted for child pid {child_pid}");
        assert!(stopped, "no ProcessStopped for child pid {child_pid}");
    }
}
