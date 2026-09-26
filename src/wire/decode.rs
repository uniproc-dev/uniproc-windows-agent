use std::sync::Arc;

use capnp::struct_list;
use uniproc_protocol::windows_capnp::{
    ProcessPriority as WirePriority, ServiceState as WireServiceState, SignatureStatus as WireSignature,
    machine_stats, process_info, process_metrics, service_stats,
};

use crate::api::{
    MachineStats, ProcessInfo, ProcessMetrics, ProcessPriority, ServiceState, ServiceStats,
    SignatureStatus,
};

fn text(reader: capnp::Result<capnp::text::Reader<'_>>) -> capnp::Result<String> {
    Ok(reader?.to_str()?.to_owned())
}

fn signature(s: Result<WireSignature, capnp::NotInSchema>) -> SignatureStatus {
    match s {
        Ok(WireSignature::Unsigned) => SignatureStatus::Unsigned,
        Ok(WireSignature::Microsoft) => SignatureStatus::Microsoft,
        Ok(WireSignature::ThirdParty) => SignatureStatus::ThirdParty,
        Ok(WireSignature::Unknown) | Err(_) => SignatureStatus::Unknown,
    }
}

fn service_state(s: Result<WireServiceState, capnp::NotInSchema>) -> ServiceState {
    match s {
        Ok(WireServiceState::Stopped) => ServiceState::Stopped,
        Ok(WireServiceState::StartPending) => ServiceState::StartPending,
        Ok(WireServiceState::StopPending) => ServiceState::StopPending,
        Ok(WireServiceState::Running) => ServiceState::Running,
        Ok(WireServiceState::ContinuePending) => ServiceState::ContinuePending,
        Ok(WireServiceState::PausePending) => ServiceState::PausePending,
        Ok(WireServiceState::Paused) => ServiceState::Paused,
        Ok(WireServiceState::Unknown) | Err(_) => ServiceState::Unknown,
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

pub fn machine(m: machine_stats::Reader<'_>) -> MachineStats {
    MachineStats {
        total_physical_kb: m.get_total_physical_kb(),
        available_physical_kb: m.get_available_physical_kb(),
        used_physical_kb: m.get_used_physical_kb(),
        cpu_percent: m.get_cpu_percent(),
        cpu_max_mhz: m.get_cpu_max_mhz(),
        cpu_current_mhz: m.get_cpu_current_mhz(),
        cpu_interrupt_percent: m.get_cpu_interrupt_percent(),
        cpu_dpc_percent: m.get_cpu_dpc_percent(),
        disk_read_bytes: m.get_disk_read_bytes(),
        disk_write_bytes: m.get_disk_write_bytes(),
        disk_read_iops: m.get_disk_read_iops(),
        disk_write_iops: m.get_disk_write_iops(),
        net_rx_bytes: m.get_net_rx_bytes(),
        net_tx_bytes: m.get_net_tx_bytes(),
    }
}

pub fn services(list: struct_list::Reader<'_, service_stats::Owned>) -> capnp::Result<Arc<[ServiceStats]>> {
    list.iter()
        .map(|s| {
            Ok(ServiceStats {
                name: text(s.get_name())?,
                display_name: text(s.get_display_name())?,
                pid: s.get_pid(),
                state: service_state(s.get_state()),
                load_group: text(s.get_load_group())?,
                description: text(s.get_description())?,
                image_path: text(s.get_image_path())?,
            })
        })
        .collect()
}

pub fn processes(list: struct_list::Reader<'_, process_info::Owned>) -> capnp::Result<Arc<[ProcessInfo]>> {
    list.iter()
        .map(|p| {
            Ok(ProcessInfo {
                pid: p.get_pid(),
                parent_pid: p.get_parent_pid(),
                session_id: p.get_session_id(),
                name: text(p.get_name())?,
                cmdline: p
                    .get_cmdline()?
                    .iter()
                    .map(text)
                    .collect::<capnp::Result<_>>()?,
                package_full_name: text(p.get_package_full_name())?,
                package_relative_app_id: text(p.get_package_relative_app_id())?,
                is_service: p.get_is_service(),
                is_kernel_process: p.get_is_kernel_process(),
                is_windows_process: p.get_is_windows_process(),
                signature: signature(p.get_signature()),
                image_path: text(p.get_image_path())?,
                display_name: text(p.get_display_name())?,
                console_host_pid: p.get_console_host_pid(),
            })
        })
        .collect()
}

pub fn metrics(list: struct_list::Reader<'_, process_metrics::Owned>) -> Vec<ProcessMetrics> {
    list.iter()
        .map(|m| ProcessMetrics {
            pid: m.get_pid(),
            cpu_percent: m.get_cpu_percent(),
            working_set_kb: m.get_working_set_kb(),
            private_bytes_kb: m.get_private_bytes_kb(),
            peak_working_set_kb: m.get_peak_working_set_kb(),
            private_working_set_kb: m.get_private_working_set_kb(),
            disk_read_bytes: m.get_disk_read_bytes(),
            disk_write_bytes: m.get_disk_write_bytes(),
            disk_read_iops: m.get_disk_read_iops(),
            disk_write_iops: m.get_disk_write_iops(),
            net_rx_bytes: m.get_net_rx_bytes(),
            net_tx_bytes: m.get_net_tx_bytes(),
        })
        .collect()
}
