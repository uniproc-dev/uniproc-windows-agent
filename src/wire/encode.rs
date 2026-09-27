use uniproc_protocol::windows_capnp::{
    Architecture as WireArchitecture, DpiAwareness as WireDpi, ExtendedCfg as WireExtendedCfg,
    IoPriority as WireIoPriority, Isolation as WireIsolation, MachineMetric as WireMachineMetric,
    ProcessMetric as WireProcessMetric, ProcessPriority as WirePriority, ServiceState as WireServiceState,
    SignatureStatus as WireSignature, StackProtection as WireStackProtection, Toggle,
    UacVirtualization as WireUac, machine_sample, metric_spec, process_columns, sampler,
    service_status, windows_agent,
};

use crate::api::{
    Architecture, DpiAwareness, ExtendedCfg, IoPriority, Isolation, MachineMetric, MachineSample,
    MetricSpec, ProcessInfo, ProcessMetric, ProcessPriority, ProcessStates, Sample, ServiceState,
    ServiceStats, ServiceStatus, SignatureStatus, StackProtection, UacVirtualization,
};

fn signature(s: SignatureStatus) -> WireSignature {
    match s {
        SignatureStatus::Unknown => WireSignature::Unknown,
        SignatureStatus::Unsigned => WireSignature::Unsigned,
        SignatureStatus::Microsoft => WireSignature::Microsoft,
        SignatureStatus::ThirdParty => WireSignature::ThirdParty,
    }
}

fn service_state(s: ServiceState) -> WireServiceState {
    match s {
        ServiceState::Unknown => WireServiceState::Unknown,
        ServiceState::Stopped => WireServiceState::Stopped,
        ServiceState::StartPending => WireServiceState::StartPending,
        ServiceState::StopPending => WireServiceState::StopPending,
        ServiceState::Running => WireServiceState::Running,
        ServiceState::ContinuePending => WireServiceState::ContinuePending,
        ServiceState::PausePending => WireServiceState::PausePending,
        ServiceState::Paused => WireServiceState::Paused,
    }
}

pub fn priority(p: ProcessPriority) -> WirePriority {
    match p {
        ProcessPriority::Idle => WirePriority::Idle,
        ProcessPriority::BelowNormal => WirePriority::BelowNormal,
        ProcessPriority::Normal => WirePriority::Normal,
        ProcessPriority::AboveNormal => WirePriority::AboveNormal,
        ProcessPriority::High => WirePriority::High,
        ProcessPriority::Realtime => WirePriority::Realtime,
    }
}

fn toggle(value: Option<bool>) -> Toggle {
    match value {
        None => Toggle::Unknown,
        Some(false) => Toggle::Off,
        Some(true) => Toggle::On,
    }
}

fn architecture(a: Architecture) -> WireArchitecture {
    match a {
        Architecture::Unknown => WireArchitecture::Unknown,
        Architecture::X86 => WireArchitecture::X86,
        Architecture::X64 => WireArchitecture::X64,
        Architecture::Arm => WireArchitecture::Arm,
        Architecture::Arm64 => WireArchitecture::Arm64,
        Architecture::Arm64X86Compatible => WireArchitecture::Arm64X86Compatible,
        Architecture::Arm64X64Compatible => WireArchitecture::Arm64X64Compatible,
    }
}

fn uac_virtualization(u: UacVirtualization) -> WireUac {
    match u {
        UacVirtualization::Unknown => WireUac::Unknown,
        UacVirtualization::NotAllowed => WireUac::NotAllowed,
        UacVirtualization::Disabled => WireUac::Disabled,
        UacVirtualization::Enabled => WireUac::Enabled,
    }
}

fn isolation(i: Isolation) -> WireIsolation {
    match i {
        Isolation::Unknown => WireIsolation::Unknown,
        Isolation::None => WireIsolation::None,
        Isolation::AppContainer => WireIsolation::AppContainer,
        Isolation::Uwp => WireIsolation::Uwp,
        Isolation::Silo => WireIsolation::Silo,
    }
}

fn dpi_awareness(d: DpiAwareness) -> WireDpi {
    match d {
        DpiAwareness::Unknown => WireDpi::Unknown,
        DpiAwareness::Unaware => WireDpi::Unaware,
        DpiAwareness::System => WireDpi::System,
        DpiAwareness::PerMonitor => WireDpi::PerMonitor,
        DpiAwareness::PerMonitorV2 => WireDpi::PerMonitorV2,
        DpiAwareness::UnawareGdiScaled => WireDpi::UnawareGdiScaled,
    }
}

fn stack_protection(s: StackProtection) -> WireStackProtection {
    match s {
        StackProtection::Unknown => WireStackProtection::Unknown,
        StackProtection::Off => WireStackProtection::Off,
        StackProtection::Compatible => WireStackProtection::Compatible,
        StackProtection::Strict => WireStackProtection::Strict,
        StackProtection::CompatibleAudit => WireStackProtection::CompatibleAudit,
        StackProtection::StrictAudit => WireStackProtection::StrictAudit,
    }
}

fn extended_cfg(e: ExtendedCfg) -> WireExtendedCfg {
    match e {
        ExtendedCfg::Unknown => WireExtendedCfg::Unknown,
        ExtendedCfg::Off => WireExtendedCfg::Off,
        ExtendedCfg::Audit => WireExtendedCfg::Audit,
        ExtendedCfg::On => WireExtendedCfg::On,
    }
}

fn io_priority(p: IoPriority) -> WireIoPriority {
    match p {
        IoPriority::Unknown => WireIoPriority::Unknown,
        IoPriority::VeryLow => WireIoPriority::VeryLow,
        IoPriority::Low => WireIoPriority::Low,
        IoPriority::Normal => WireIoPriority::Normal,
        IoPriority::High => WireIoPriority::High,
        IoPriority::Critical => WireIoPriority::Critical,
    }
}

fn process_metric(m: ProcessMetric) -> WireProcessMetric {
    match m {
        ProcessMetric::CpuUserTime => WireProcessMetric::CpuUserTime,
        ProcessMetric::CpuKernelTime => WireProcessMetric::CpuKernelTime,
        ProcessMetric::CpuCycles => WireProcessMetric::CpuCycles,
        ProcessMetric::WorkingSet => WireProcessMetric::WorkingSet,
        ProcessMetric::PeakWorkingSet => WireProcessMetric::PeakWorkingSet,
        ProcessMetric::PrivateWorkingSet => WireProcessMetric::PrivateWorkingSet,
        ProcessMetric::Commit => WireProcessMetric::Commit,
        ProcessMetric::PagedPool => WireProcessMetric::PagedPool,
        ProcessMetric::NonPagedPool => WireProcessMetric::NonPagedPool,
        ProcessMetric::PageFaults => WireProcessMetric::PageFaults,
        ProcessMetric::Handles => WireProcessMetric::Handles,
        ProcessMetric::Threads => WireProcessMetric::Threads,
        ProcessMetric::UserObjects => WireProcessMetric::UserObjects,
        ProcessMetric::GdiObjects => WireProcessMetric::GdiObjects,
        ProcessMetric::IoReadOps => WireProcessMetric::IoReadOps,
        ProcessMetric::IoWriteOps => WireProcessMetric::IoWriteOps,
        ProcessMetric::IoOtherOps => WireProcessMetric::IoOtherOps,
        ProcessMetric::IoReadBytes => WireProcessMetric::IoReadBytes,
        ProcessMetric::IoWriteBytes => WireProcessMetric::IoWriteBytes,
        ProcessMetric::IoOtherBytes => WireProcessMetric::IoOtherBytes,
        ProcessMetric::DiskReadOps => WireProcessMetric::DiskReadOps,
        ProcessMetric::DiskWriteOps => WireProcessMetric::DiskWriteOps,
        ProcessMetric::DiskFlushOps => WireProcessMetric::DiskFlushOps,
        ProcessMetric::DiskReadBytes => WireProcessMetric::DiskReadBytes,
        ProcessMetric::DiskWriteBytes => WireProcessMetric::DiskWriteBytes,
        ProcessMetric::NetRxBytes => WireProcessMetric::NetRxBytes,
        ProcessMetric::NetTxBytes => WireProcessMetric::NetTxBytes,
    }
}

fn machine_metric(m: MachineMetric) -> WireMachineMetric {
    match m {
        MachineMetric::Cpu => WireMachineMetric::Cpu,
        MachineMetric::Memory => WireMachineMetric::Memory,
        MachineMetric::Disk => WireMachineMetric::Disk,
        MachineMetric::Network => WireMachineMetric::Network,
    }
}

pub fn processes(processes: &[ProcessInfo], mut out: windows_agent::get_processes_results::Builder) {
    let mut list = out.reborrow().init_processes(processes.len() as u32);
    for (i, e) in processes.iter().enumerate() {
        let mut p = list.reborrow().get(i as u32);
        p.set_pid(e.pid);
        p.set_parent_pid(e.parent_pid);
        p.set_session_id(e.session_id);
        p.set_name(&e.name);
        p.set_package_full_name(&e.package_full_name);
        p.set_package_relative_app_id(&e.package_relative_app_id);

        {
            let mut cmdline = p.reborrow().init_cmdline(e.cmdline.len() as u32);
            for (j, arg) in e.cmdline.iter().enumerate() {
                cmdline.reborrow().set(j as u32, arg);
            }
        }

        p.set_is_service(e.is_service);
        p.set_is_kernel_process(e.is_kernel_process);
        p.set_is_windows_process(e.is_windows_process);
        p.set_signature(signature(e.signature));
        p.set_image_path(&e.image_path);
        p.set_display_name(&e.display_name);
        p.set_console_host_pid(e.console_host_pid);
        p.set_start_time(e.start_time);
        p.set_sequence_number(e.sequence_number);
        p.set_user(&e.user);
        p.set_architecture(architecture(e.architecture));
        p.set_elevated(toggle(e.elevated));
        p.set_uac_virtualization(uac_virtualization(e.uac_virtualization));
        p.set_isolation(isolation(e.isolation));
        p.set_dpi_awareness(dpi_awareness(e.dpi_awareness));
        if let Some(m) = &e.mitigations {
            let mut out = p.reborrow().init_mitigations();
            out.set_dep(toggle(m.dep));
            out.set_stack_protection(stack_protection(m.stack_protection));
            out.set_extended_cfg(extended_cfg(m.extended_cfg));
        }
        p.set_publisher(&e.publisher);
    }
}

pub fn process_states(states: &ProcessStates, mut out: windows_agent::get_process_states_results::Builder) {
    out.set_passport_etag(states.passport_etag);
    let mut list = out.reborrow().init_states(states.states.len() as u32);
    for (i, e) in states.states.iter().enumerate() {
        let mut s = list.reborrow().get(i as u32);
        s.set_pid(e.pid);
        s.set_sequence_number(e.sequence_number);
        s.set_suspended(toggle(e.suspended));
        s.set_efficiency_mode(toggle(e.efficiency_mode));
        s.set_base_priority(e.base_priority.map_or(WirePriority::Unknown, priority));
        s.set_power_throttling(toggle(e.power_throttling));
        s.set_job_object_id(e.job_object_id);
        s.set_io_priority(io_priority(e.io_priority));
    }
}

pub fn services(services: &[ServiceStats], mut out: windows_agent::get_services_results::Builder) {
    let mut list = out.reborrow().init_services(services.len() as u32);
    for (i, svc) in services.iter().enumerate() {
        let mut s = list.reborrow().get(i as u32);
        s.set_name(&svc.name);
        s.set_display_name(&svc.display_name);
        s.set_pid(svc.pid);
        s.set_state(service_state(svc.state));
        s.set_load_group(&svc.load_group);
        s.set_description(&svc.description);
        s.set_image_path(&svc.image_path);
    }
}

pub fn service_status(s: &ServiceStatus, mut out: service_status::Builder) {
    out.set_state(service_state(s.state));
    out.set_pid(s.pid);
    out.set_exit_code(s.exit_code);
    out.set_service_exit_code(s.service_exit_code);
    out.set_checkpoint(s.checkpoint);
    out.set_wait_hint_ms(s.wait_hint_ms);
}

pub fn metric_spec(spec: &MetricSpec, mut out: metric_spec::Builder) {
    out.set_interval_ms(spec.interval.as_millis().min(u32::MAX as u128) as u32);
    let processes: Vec<ProcessMetric> = spec.processes.iter().collect();
    let mut list = out.reborrow().init_processes(processes.len() as u32);
    for (i, &m) in processes.iter().enumerate() {
        list.set(i as u32, process_metric(m));
    }
    let machine: Vec<MachineMetric> = spec.machine.iter().collect();
    let mut list = out.reborrow().init_machine(machine.len() as u32);
    for (i, &m) in machine.iter().enumerate() {
        list.set(i as u32, machine_metric(m));
    }
}

macro_rules! columns {
    ($out:ident, $columns:expr, $($field:ident => $set:ident,)*) => {
        $(if let Some(values) = &$columns.$field {
            $out.$set(&values[..])?;
        })*
    };
}

pub fn sample(sample: &Sample, mut out: sampler::sample_results::Builder) -> capnp::Result<()> {
    process_columns(sample, out.reborrow().init_processes())?;
    machine_sample(sample, out.init_machine());
    Ok(())
}

fn process_columns(sample: &Sample, mut out: process_columns::Builder) -> capnp::Result<()> {
    out.set_snapshot(sample.snapshot);
    out.set_sampled_at(sample.sampled_at);
    out.set_passport_etag(sample.passport_etag);
    if sample.wanted.processes.is_empty() {
        return Ok(());
    }
    out.set_pids(&sample.pids[..])?;
    out.set_sequence_numbers(&sample.sequence_numbers[..])?;
    let c = &sample.columns;
    columns!(out, c,
        cpu_user_time => set_cpu_user_time,
        cpu_kernel_time => set_cpu_kernel_time,
        cpu_cycles => set_cpu_cycles,
        working_set => set_working_set,
        peak_working_set => set_peak_working_set,
        private_working_set => set_private_working_set,
        commit => set_commit,
        paged_pool => set_paged_pool,
        non_paged_pool => set_non_paged_pool,
        page_faults => set_page_faults,
        handles => set_handles,
        threads => set_threads,
        user_objects => set_user_objects,
        gdi_objects => set_gdi_objects,
        io_read_ops => set_io_read_ops,
        io_write_ops => set_io_write_ops,
        io_other_ops => set_io_other_ops,
        io_read_bytes => set_io_read_bytes,
        io_write_bytes => set_io_write_bytes,
        io_other_bytes => set_io_other_bytes,
        disk_read_ops => set_disk_read_ops,
        disk_write_ops => set_disk_write_ops,
        disk_flush_ops => set_disk_flush_ops,
        disk_read_bytes => set_disk_read_bytes,
        disk_write_bytes => set_disk_write_bytes,
        net_rx_bytes => set_net_rx_bytes,
        net_tx_bytes => set_net_tx_bytes,
    );
    Ok(())
}

fn machine_sample(sample: &Sample, mut out: machine_sample::Builder) {
    out.set_snapshot(sample.snapshot);
    out.set_sampled_at(sample.sampled_at);
    let MachineSample {
        cpu,
        memory,
        disk,
        network,
    } = &sample.machine;
    if let Some(cpu) = cpu {
        let mut c = out.reborrow().init_cpu();
        c.set_idle_time(cpu.idle_time);
        c.set_kernel_time(cpu.kernel_time);
        c.set_user_time(cpu.user_time);
        c.set_interrupt_time(cpu.interrupt_time);
        c.set_dpc_time(cpu.dpc_time);
        c.set_max_mhz(cpu.max_mhz);
        c.set_current_mhz(cpu.current_mhz);
    }
    if let Some(memory) = memory {
        let mut m = out.reborrow().init_memory();
        m.set_total_physical(memory.total_physical);
        m.set_available_physical(memory.available_physical);
    }
    if let Some(disk) = disk {
        let mut d = out.reborrow().init_disk();
        d.set_read_ops(disk.read_ops);
        d.set_write_ops(disk.write_ops);
        d.set_read_bytes(disk.read_bytes);
        d.set_write_bytes(disk.write_bytes);
    }
    if let Some(network) = network {
        let mut n = out.reborrow().init_network();
        n.set_rx_bytes(network.rx_bytes);
        n.set_tx_bytes(network.tx_bytes);
    }
}
