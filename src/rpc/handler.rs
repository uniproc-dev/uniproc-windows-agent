use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use uniproc_protocol::windows_capnp::{ProcessPriority as ProtoPriority, windows_agent};

use crate::commands::process::ProcessPriority;
use crate::commands::{Commands, Outcome};
use crate::monitor::SharedSupervisor;
use crate::settings::CollectorSettings;
use crate::state::SystemState;

#[derive(Clone)]
pub struct AgentImpl {
    supervisor: SharedSupervisor,
    state: Arc<parking_lot::Mutex<SystemState>>,
    settings: CollectorSettings,
    commands: Commands,
}

impl AgentImpl {
    pub fn new(
        supervisor: SharedSupervisor,
        state: Arc<parking_lot::Mutex<SystemState>>,
        settings: CollectorSettings,
        commands: Commands,
    ) -> Self {
        Self {
            supervisor,
            state,
            settings,
            commands,
        }
    }
}

fn code(outcome: Outcome) -> u32 {
    outcome.err().unwrap_or(0)
}

fn name(params: capnp::text::Reader) -> Result<String, capnp::Error> {
    Ok(params.to_str()?.to_owned())
}

fn priority(p: ProtoPriority) -> ProcessPriority {
    match p {
        ProtoPriority::Idle => ProcessPriority::Idle,
        ProtoPriority::BelowNormal => ProcessPriority::BelowNormal,
        ProtoPriority::Normal => ProcessPriority::Normal,
        ProtoPriority::AboveNormal => ProcessPriority::AboveNormal,
        ProtoPriority::High => ProcessPriority::High,
        ProtoPriority::Realtime => ProcessPriority::Realtime,
    }
}

macro_rules! service_method {
    ($method:ident, $params:ident, $results:ident, $call:ident) => {
        async fn $method(
            self: Rc<Self>,
            params: windows_agent::$params,
            mut results: windows_agent::$results,
        ) -> Result<(), capnp::Error> {
            let service_name = name(params.get()?.get_name()?)?;
            let outcome = self.commands.$call(service_name).await;
            results.get().set_code(code(outcome));
            Ok(())
        }
    };
}

impl windows_agent::Server for AgentImpl {
    async fn ping(
        self: Rc<Self>,
        _: windows_agent::PingParams,
        _: windows_agent::PingResults,
    ) -> Result<(), capnp::Error> {
        Ok(())
    }

    async fn get_report(
        self: Rc<Self>,
        _: windows_agent::GetReportParams,
        mut results: windows_agent::GetReportResults,
    ) -> Result<(), capnp::Error> {
        {
            let mut supervisor = self.supervisor.lock();
            supervisor.tick();
        }
        crate::rpc::mapping::build_report(&self.state.lock(), results.get().init_report());
        Ok(())
    }

    async fn set_config(
        self: Rc<Self>,
        params: windows_agent::SetConfigParams,
        _: windows_agent::SetConfigResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let memory_interval_ms = params.get_memory_interval_ms();
        let cpu_interval_ms = params.get_cpu_interval_ms();
        if memory_interval_ms > 0 {
            self.settings
                .set_memory_interval(Duration::from_millis(memory_interval_ms));
        }
        if cpu_interval_ms > 0 {
            self.settings
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
        let outcome = self.commands.process_kill(pid).await;
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn suspend(
        self: Rc<Self>,
        params: windows_agent::SuspendParams,
        mut results: windows_agent::SuspendResults,
    ) -> Result<(), capnp::Error> {
        let pid = params.get()?.get_pid();
        let outcome = self.commands.process_suspend(pid).await;
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn resume(
        self: Rc<Self>,
        params: windows_agent::ResumeParams,
        mut results: windows_agent::ResumeResults,
    ) -> Result<(), capnp::Error> {
        let pid = params.get()?.get_pid();
        let outcome = self.commands.process_resume(pid).await;
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn set_priority(
        self: Rc<Self>,
        params: windows_agent::SetPriorityParams,
        mut results: windows_agent::SetPriorityResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let outcome = self
            .commands
            .process_set_priority(params.get_pid(), priority(params.get_priority()?))
            .await;
        results.get().set_code(code(outcome));
        Ok(())
    }

    async fn set_affinity(
        self: Rc<Self>,
        params: windows_agent::SetAffinityParams,
        mut results: windows_agent::SetAffinityResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let outcome = self
            .commands
            .process_set_affinity(params.get_pid(), params.get_mask())
            .await;
        results.get().set_code(code(outcome));
        Ok(())
    }

    service_method!(service_start, ServiceStartParams, ServiceStartResults, service_start);
    service_method!(service_stop, ServiceStopParams, ServiceStopResults, service_stop);
    service_method!(service_pause, ServicePauseParams, ServicePauseResults, service_pause);
    service_method!(service_resume, ServiceResumeParams, ServiceResumeResults, service_resume);
    service_method!(service_restart, ServiceRestartParams, ServiceRestartResults, service_restart);
}
