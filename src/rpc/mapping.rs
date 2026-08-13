use uniproc_protocol::windows_capnp::{
    ServiceState as WireServiceState, SignatureStatus, machine_stats, report,
};

use crate::providers::utils::ServiceState;
use crate::state::SystemState;
use crate::state::events::ProcessSignature;

fn signature_status(s: ProcessSignature) -> SignatureStatus {
    match s {
        ProcessSignature::Unknown => SignatureStatus::Unknown,
        ProcessSignature::Unsigned => SignatureStatus::Unsigned,
        ProcessSignature::Microsoft => SignatureStatus::Microsoft,
        ProcessSignature::ThirdParty => SignatureStatus::ThirdParty,
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

pub fn build_report(state: &SystemState, mut out: report::Builder) {
    build_machine_stats(state, out.reborrow().init_machine());
    build_services(state, &mut out);

    let mut list = out.reborrow().init_processes(state.len() as u32);
    for (i, e) in state.entries().enumerate() {
        let mut p = list.reborrow().get(i as u32);
        p.set_pid(e.pid);
        p.set_parent_pid(e.parent_pid);
        p.set_session_id(e.session_id);
        p.set_name(&e.image_name);
        p.set_package_full_name(&e.package_name);
        p.set_package_relative_app_id(&e.package_relative_app_id);
        p.set_cpu_percent(e.cpu.total_percent as f32);

        {
            let mut cmdline = p.reborrow().init_cmdline(e.command_line.len() as u32);
            for (j, arg) in e.command_line.iter().enumerate() {
                cmdline.reborrow().set(j as u32, arg);
            }
        }

        let mem = e.memory.as_ref();
        p.set_working_set_kb(mem.map(|m| m.working_set_bytes / 1024).unwrap_or(0));
        p.set_private_bytes_kb(mem.map(|m| m.private_bytes / 1024).unwrap_or(0));
        p.set_peak_working_set_kb(mem.map(|m| m.peak_working_set_bytes / 1024).unwrap_or(0));
        p.set_private_working_set_kb(mem.map(|m| m.private_working_set_bytes / 1024).unwrap_or(0));

        p.set_disk_read_bytes(e.disk.read_bytes);
        p.set_disk_write_bytes(e.disk.write_bytes);
        p.set_disk_read_iops(e.disk.read_ops);
        p.set_disk_write_iops(e.disk.write_ops);

        p.set_net_rx_bytes(e.network.recv_bytes);
        p.set_net_tx_bytes(e.network.sent_bytes);

        p.set_is_service(state.is_service(e.pid));
        p.set_is_kernel_process(e.is_kernel_process);
        p.set_is_windows_process(e.is_windows_process);
        p.set_signature(signature_status(e.signature));
        p.set_image_path(&e.image_path);
        p.set_display_name(&e.display_name);
    }
}

fn build_services(state: &SystemState, out: &mut report::Builder) {
    let services = state.services();
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

fn build_machine_stats(state: &SystemState, mut out: machine_stats::Builder) {
    if let Some(m) = state.machine() {
        out.set_total_physical_kb(m.total_physical_kb);
        out.set_available_physical_kb(m.available_physical_kb);
        out.set_used_physical_kb(m.used_physical_kb);
        out.set_cpu_percent(m.cpu_percent);
        out.set_cpu_max_mhz(m.cpu_max_mhz);
        out.set_cpu_current_mhz(m.cpu_current_mhz);
    }

    let totals = state.machine_totals();
    out.set_disk_read_bytes(totals.disk_read_bytes);
    out.set_disk_write_bytes(totals.disk_write_bytes);
    out.set_disk_read_iops(totals.disk_read_ops);
    out.set_disk_write_iops(totals.disk_write_ops);
    out.set_net_rx_bytes(totals.net_rx_bytes);
    out.set_net_tx_bytes(totals.net_tx_bytes);
}
