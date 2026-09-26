use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::channel::oneshot;
use futures::future::{Either, select};
use uniproc_protocol::meta_capnp::{self, ResponseStatus};
use uniproc_protocol::windows_capnp::{service_watcher, watch_handle, windows_agent};

use uniproc_windows_agent::api::{Command, CommandResult};
use uniproc_windows_agent::local::{Local, ServiceWatch};
use uniproc_windows_agent::wire::{decode, encode};

#[derive(Clone)]
pub struct AgentImpl {
    agent: Arc<Local>,
}

impl AgentImpl {
    pub fn new(agent: Arc<Local>) -> Self {
        Self { agent }
    }

    /// A command that panicked fails the call rather than answer a code.
    async fn run(&self, command: Command) -> Result<CommandResult, capnp::Error> {
        self.agent
            .run(command)
            .await
            .map_err(|e| capnp::Error::failed(format!("{e:#}")))
    }
}

struct WatchHandleImpl {
    _release: oneshot::Sender<()>,
}

impl watch_handle::Server for WatchHandleImpl {}

async fn forward(
    mut watch: ServiceWatch,
    watcher: service_watcher::Client,
    mut released: oneshot::Receiver<()>,
) {
    loop {
        let status = match select(&mut released, watch.next()).await {
            Either::Left(_) => return,
            Either::Right((Some(status), _)) => status,
            Either::Right((None, _)) => break,
        };
        let mut request = watcher.changed_request();
        request.get().init_meta();
        encode::service_status(&status, request.get().init_status());
        if request.send().promise.await.is_err() {
            return;
        }
    }
    let mut request = watcher.ended_request();
    request.get().init_meta();
    let _ = request.send().promise.await;
}

fn code(outcome: CommandResult) -> u32 {
    outcome.err().unwrap_or(0)
}

fn unconditional(mut meta: meta_capnp::response_meta::Builder) {
    meta.set_etag(0);
    meta.set_status(ResponseStatus::Ok);
}

fn conditional(mut meta: meta_capnp::response_meta::Builder, if_none_match: u64, etag: u64) -> bool {
    meta.set_etag(etag);
    if if_none_match != 0 && if_none_match == etag {
        meta.set_status(ResponseStatus::NotModified);
        false
    } else {
        meta.set_status(ResponseStatus::Ok);
        true
    }
}

fn name(params: capnp::text::Reader) -> Result<String, capnp::Error> {
    Ok(params.to_str()?.to_owned())
}

macro_rules! service_method {
    ($method:ident, $params:ident, $results:ident, $command:ident) => {
        async fn $method(
            self: Rc<Self>,
            params: windows_agent::$params,
            mut results: windows_agent::$results,
        ) -> Result<(), capnp::Error> {
            let name = name(params.get()?.get_name()?)?;
            let outcome = self.run(Command::$command { name }).await?;
            unconditional(results.get().init_meta());
            results.get().set_code(code(outcome));
            Ok(())
        }
    };
}

impl windows_agent::Server for AgentImpl {
    async fn ping(
        self: Rc<Self>,
        params: windows_agent::PingParams,
        mut results: windows_agent::PingResults,
    ) -> Result<(), capnp::Error> {
        let nonce = params.get()?.get_nonce();
        unconditional(results.get().init_meta());
        results.get().set_nonce(nonce);
        Ok(())
    }

    async fn get_machine(
        self: Rc<Self>,
        _: windows_agent::GetMachineParams,
        mut results: windows_agent::GetMachineResults,
    ) -> Result<(), capnp::Error> {
        let machine = self.agent.machine();
        unconditional(results.get().init_meta());
        encode::machine(&machine, results.get().init_machine());
        Ok(())
    }

    async fn get_services(
        self: Rc<Self>,
        params: windows_agent::GetServicesParams,
        mut results: windows_agent::GetServicesResults,
    ) -> Result<(), capnp::Error> {
        let if_none_match = params.get()?.get_meta()?.get_if_none_match();
        let services = self.agent.services();
        if conditional(results.get().init_meta(), if_none_match, services.etag) {
            encode::services(&services.value, results.get());
        }
        Ok(())
    }

    async fn get_processes(
        self: Rc<Self>,
        params: windows_agent::GetProcessesParams,
        mut results: windows_agent::GetProcessesResults,
    ) -> Result<(), capnp::Error> {
        let if_none_match = params.get()?.get_meta()?.get_if_none_match();
        let processes = self.agent.processes();
        if conditional(results.get().init_meta(), if_none_match, processes.etag) {
            encode::processes(&processes.value, results.get());
        }
        Ok(())
    }

    async fn get_process_metrics(
        self: Rc<Self>,
        _: windows_agent::GetProcessMetricsParams,
        mut results: windows_agent::GetProcessMetricsResults,
    ) -> Result<(), capnp::Error> {
        let snapshot = self.agent.process_metrics();
        unconditional(results.get().init_meta());
        encode::process_metrics(&snapshot, results.get());
        Ok(())
    }

    async fn set_config(
        self: Rc<Self>,
        params: windows_agent::SetConfigParams,
        mut results: windows_agent::SetConfigResults,
    ) -> Result<(), capnp::Error> {
        unconditional(results.get().init_meta());
        let params = params.get()?;
        let memory_interval_ms = params.get_memory_interval_ms();
        let cpu_interval_ms = params.get_cpu_interval_ms();
        if memory_interval_ms > 0 {
            self.agent
                .set_memory_interval(Duration::from_millis(memory_interval_ms));
        }
        if cpu_interval_ms > 0 {
            self.agent
                .set_cpu_interval(Duration::from_millis(cpu_interval_ms));
        }
        Ok(())
    }

    async fn kill(
        self: Rc<Self>,
        params: windows_agent::KillParams,
        mut results: windows_agent::KillResults,
    ) -> Result<(), capnp::Error> {
        let pid = params.get()?.get_pid();
        let outcome = self.run(Command::Kill { pid }).await?;
        unconditional(results.get().init_meta());
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn suspend(
        self: Rc<Self>,
        params: windows_agent::SuspendParams,
        mut results: windows_agent::SuspendResults,
    ) -> Result<(), capnp::Error> {
        let pid = params.get()?.get_pid();
        let outcome = self.run(Command::Suspend { pid }).await?;
        unconditional(results.get().init_meta());
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn resume(
        self: Rc<Self>,
        params: windows_agent::ResumeParams,
        mut results: windows_agent::ResumeResults,
    ) -> Result<(), capnp::Error> {
        let pid = params.get()?.get_pid();
        let outcome = self.run(Command::Resume { pid }).await?;
        unconditional(results.get().init_meta());
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn set_priority(
        self: Rc<Self>,
        params: windows_agent::SetPriorityParams,
        mut results: windows_agent::SetPriorityResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let pid = params.get_pid();
        let priority = decode::priority(params.get_priority()?);
        let outcome = self.run(Command::SetPriority { pid, priority }).await?;
        unconditional(results.get().init_meta());
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn set_affinity(
        self: Rc<Self>,
        params: windows_agent::SetAffinityParams,
        mut results: windows_agent::SetAffinityResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let pid = params.get_pid();
        let mask = params.get_mask();
        let outcome = self.run(Command::SetAffinity { pid, mask }).await?;
        unconditional(results.get().init_meta());
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn watch_service(
        self: Rc<Self>,
        params: windows_agent::WatchServiceParams,
        mut results: windows_agent::WatchServiceResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let name = name(params.get_name()?)?;
        let watcher = params.get_watcher()?;
        let (release, released) = oneshot::channel();
        compio::runtime::spawn(forward(self.agent.watch_service(&name), watcher, released)).detach();
        unconditional(results.get().init_meta());
        results
            .get()
            .set_handle(capnp_rpc::new_client(WatchHandleImpl { _release: release }));
        Ok(())
    }

    service_method!(service_start, ServiceStartParams, ServiceStartResults, ServiceStart);
    service_method!(service_stop, ServiceStopParams, ServiceStopResults, ServiceStop);
    service_method!(service_pause, ServicePauseParams, ServicePauseResults, ServicePause);
    service_method!(service_resume, ServiceResumeParams, ServiceResumeResults, ServiceResume);
    service_method!(service_restart, ServiceRestartParams, ServiceRestartResults, ServiceRestart);
}
