use uniproc_protocol::windows_capnp::{
    ProcessPriority as WirePriority, ServiceState as WireServiceState, SignatureStatus as WireSignature,
    machine_stats, windows_agent,
};

use crate::api::{
    MachineStats, ProcessInfo, ProcessMetricsSnapshot, ProcessPriority, ServiceState, ServiceStats,
    SignatureStatus,
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

pub fn priority(p: WirePriority) -> ProcessPriority {
    match p {
        WirePriority::Idle => ProcessPriority::Idle,
        WirePriority::BelowNormal => ProcessPriority::BelowNormal,
        WirePriority::Normal => ProcessPriority::Normal,
        WirePriority::AboveNormal => ProcessPriority::AboveNormal,
        WirePriority::High => ProcessPriority::High,
        WirePriority::Realtime => ProcessPriority::Realtime,
    }
}

pub fn build_processes(processes: &[ProcessInfo], mut out: windows_agent::get_processes_results::Builder) {
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
    }
}

pub fn build_process_metrics(
    snapshot: &ProcessMetricsSnapshot,
    mut out: windows_agent::get_process_metrics_results::Builder,
) {
    out.set_processes_etag(snapshot.processes_etag);
    let mut list = out.reborrow().init_metrics(snapshot.metrics.len() as u32);
    for (i, e) in snapshot.metrics.iter().enumerate() {
        let mut m = list.reborrow().get(i as u32);
        m.set_pid(e.pid);
        m.set_cpu_percent(e.cpu_percent);
        m.set_working_set_kb(e.working_set_kb);
        m.set_private_bytes_kb(e.private_bytes_kb);
        m.set_peak_working_set_kb(e.peak_working_set_kb);
        m.set_private_working_set_kb(e.private_working_set_kb);
        m.set_disk_read_bytes(e.disk_read_bytes);
        m.set_disk_write_bytes(e.disk_write_bytes);
        m.set_disk_read_iops(e.disk_read_iops);
        m.set_disk_write_iops(e.disk_write_iops);
        m.set_net_rx_bytes(e.net_rx_bytes);
        m.set_net_tx_bytes(e.net_tx_bytes);
    }
}

pub fn build_services(services: &[ServiceStats], mut out: windows_agent::get_services_results::Builder) {
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

pub fn build_machine(m: &MachineStats, mut out: machine_stats::Builder) {
    out.set_total_physical_kb(m.total_physical_kb);
    out.set_available_physical_kb(m.available_physical_kb);
    out.set_used_physical_kb(m.used_physical_kb);
    out.set_cpu_percent(m.cpu_percent);
    out.set_cpu_max_mhz(m.cpu_max_mhz);
    out.set_cpu_current_mhz(m.cpu_current_mhz);
    out.set_cpu_interrupt_percent(m.cpu_interrupt_percent);
    out.set_cpu_dpc_percent(m.cpu_dpc_percent);
    out.set_disk_read_bytes(m.disk_read_bytes);
    out.set_disk_write_bytes(m.disk_write_bytes);
    out.set_disk_read_iops(m.disk_read_iops);
    out.set_disk_write_iops(m.disk_write_iops);
    out.set_net_rx_bytes(m.net_rx_bytes);
    out.set_net_tx_bytes(m.net_tx_bytes);
}
