use std::sync::Arc;

use crate::api::{
    MachineStats, ProcessInfo, ProcessMetrics, ProcessMetricsSnapshot, ServiceState,
    ServiceStats, SignatureStatus,
};
use crate::providers::utils::ServiceState as InventoryState;
use crate::state::SystemState;
use crate::state::events::ProcessSignature;

fn signature(s: ProcessSignature) -> SignatureStatus {
    match s {
        ProcessSignature::Unknown => SignatureStatus::Unknown,
        ProcessSignature::Unsigned => SignatureStatus::Unsigned,
        ProcessSignature::Microsoft => SignatureStatus::Microsoft,
        ProcessSignature::ThirdParty => SignatureStatus::ThirdParty,
    }
}

fn service_state(s: InventoryState) -> ServiceState {
    match s {
        InventoryState::Unknown => ServiceState::Unknown,
        InventoryState::Stopped => ServiceState::Stopped,
        InventoryState::StartPending => ServiceState::StartPending,
        InventoryState::StopPending => ServiceState::StopPending,
        InventoryState::Running => ServiceState::Running,
        InventoryState::ContinuePending => ServiceState::ContinuePending,
        InventoryState::PausePending => ServiceState::PausePending,
        InventoryState::Paused => ServiceState::Paused,
    }
}

pub fn processes(state: &SystemState) -> Arc<[ProcessInfo]> {
    state
        .entries()
        .map(|e| ProcessInfo {
            pid: e.pid,
            parent_pid: e.parent_pid,
            session_id: e.session_id,
            name: e.image_name.clone(),
            cmdline: e.command_line.clone(),
            package_full_name: e.package_name.clone(),
            package_relative_app_id: e.package_relative_app_id.clone(),
            is_service: state.is_service(e.pid),
            is_kernel_process: e.is_kernel_process,
            is_windows_process: e.is_windows_process,
            signature: signature(e.signature),
            image_path: e.image_path.clone(),
            display_name: e.display_name.clone(),
            console_host_pid: e.console_host_pid,
        })
        .collect()
}

pub fn process_metrics(state: &SystemState) -> ProcessMetricsSnapshot {
    let metrics = state
        .entries()
        .map(|e| {
            let mem = e.memory.as_ref();
            ProcessMetrics {
                pid: e.pid,
                cpu_percent: e.cpu.total_percent as f32,
                working_set_kb: mem.map_or(0, |m| m.working_set_bytes / 1024),
                private_bytes_kb: mem.map_or(0, |m| m.private_bytes / 1024),
                peak_working_set_kb: mem.map_or(0, |m| m.peak_working_set_bytes / 1024),
                private_working_set_kb: mem.map_or(0, |m| m.private_working_set_bytes / 1024),
                disk_read_bytes: e.disk.read_bytes,
                disk_write_bytes: e.disk.write_bytes,
                disk_read_iops: e.disk.read_ops,
                disk_write_iops: e.disk.write_ops,
                net_rx_bytes: e.network.recv_bytes,
                net_tx_bytes: e.network.sent_bytes,
            }
        })
        .collect();
    ProcessMetricsSnapshot {
        processes_etag: state.processes_etag(),
        metrics,
    }
}

pub fn services(state: &SystemState) -> Arc<[ServiceStats]> {
    state
        .services()
        .iter()
        .map(|s| ServiceStats {
            name: s.name.clone(),
            display_name: s.display_name.clone(),
            pid: s.pid,
            state: service_state(s.state),
            load_group: s.load_group.clone(),
            description: s.description.clone(),
            image_path: s.image_path.clone(),
        })
        .collect()
}

pub fn machine(state: &SystemState) -> MachineStats {
    let totals = state.machine_totals();
    let mut out = MachineStats {
        disk_read_bytes: totals.disk_read_bytes,
        disk_write_bytes: totals.disk_write_bytes,
        disk_read_iops: totals.disk_read_ops,
        disk_write_iops: totals.disk_write_ops,
        net_rx_bytes: totals.net_rx_bytes,
        net_tx_bytes: totals.net_tx_bytes,
        ..Default::default()
    };
    if let Some(m) = state.machine() {
        out.total_physical_kb = m.total_physical_kb;
        out.available_physical_kb = m.available_physical_kb;
        out.used_physical_kb = m.used_physical_kb;
        out.cpu_percent = m.cpu_percent;
        out.cpu_max_mhz = m.cpu_max_mhz;
        out.cpu_current_mhz = m.cpu_current_mhz;
        out.cpu_interrupt_percent = m.cpu_interrupt_percent;
        out.cpu_dpc_percent = m.cpu_dpc_percent;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::utils::ServiceInfo;
    use crate::state::events::{MemorySnapshot, ProcessStarted, StateChange};

    fn state() -> SystemState {
        let mut s = SystemState::new();
        s.apply(StateChange::ProcessStarted(Box::new(ProcessStarted {
            pid: 100,
            parent_pid: 4,
            session_id: 1,
            image_name: "a.exe".to_string(),
            command_line: vec!["a.exe".to_string(), "-x".to_string()],
            package_full_name: String::new(),
            package_relative_app_id: String::new(),
            is_kernel_process: false,
        })));
        s.apply(StateChange::Memory(vec![MemorySnapshot {
            pid: 100,
            working_set_bytes: 8192,
            private_working_set_bytes: 4096,
            ..Default::default()
        }]));
        s.apply(StateChange::ServicesSnapshot(vec![ServiceInfo {
            name: "svc".to_string(),
            pid: 100,
            state: InventoryState::Running,
            ..Default::default()
        }]));
        s
    }

    #[test]
    fn a_process_is_listed_with_what_it_is() {
        let listed = processes(&state());
        assert_eq!(listed.len(), 1);
        let p = &listed[0];
        assert_eq!((p.pid, p.parent_pid, p.session_id), (100, 4, 1));
        assert_eq!(p.name, "a.exe");
        assert_eq!(p.cmdline, ["a.exe", "-x"]);
        assert!(p.is_service, "a service runs in it");
    }

    #[test]
    fn metrics_are_in_kilobytes_and_carry_the_processes_tag() {
        let s = state();
        let snapshot = process_metrics(&s);
        assert_eq!(snapshot.processes_etag, s.processes_etag());
        assert_eq!(snapshot.metrics.len(), 1);
        assert_eq!(snapshot.metrics[0].working_set_kb, 8);
        assert_eq!(snapshot.metrics[0].private_working_set_kb, 4);
    }

    #[test]
    fn a_service_keeps_its_state() {
        let listed = services(&state());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "svc");
        assert_eq!(listed[0].state, ServiceState::Running);
    }

    #[test]
    fn a_machine_not_sampled_yet_is_all_zero() {
        assert_eq!(machine(&SystemState::new()), MachineStats::default());
    }
}
