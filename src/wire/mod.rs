//! The `api` structs to and from the pipe's capnp messages; the client decodes what the service encodes.

pub mod decode;
pub mod encode;

#[cfg(test)]
mod tests {
    use uniproc_protocol::windows_capnp::{machine_stats, service_status, windows_agent};
    use windows_agent::{get_process_metrics_results, get_processes_results, get_services_results};

    use super::{decode, encode};
    use crate::api::{
        MachineStats, ProcessInfo, ProcessMetrics, ProcessMetricsSnapshot, ProcessPriority,
        ServiceState, ServiceStats, ServiceStatus, SignatureStatus,
    };

    fn process(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: 4,
            session_id: 1,
            name: "a.exe".into(),
            cmdline: vec!["a.exe".into(), "--flag".into()],
            package_full_name: "Pkg_1.0_x64__abc".into(),
            package_relative_app_id: "App".into(),
            is_service: true,
            is_kernel_process: false,
            is_windows_process: true,
            signature: SignatureStatus::ThirdParty,
            image_path: "C:\\a.exe".into(),
            display_name: "A".into(),
            console_host_pid: 77,
        }
    }

    #[test]
    fn a_process_list_survives_the_wire() {
        let sent = [process(100), process(200)];
        let mut message = capnp::message::Builder::new_default();
        encode::processes(&sent, message.init_root::<get_processes_results::Builder>());
        let reader = message.get_root_as_reader::<get_processes_results::Reader>().unwrap();
        assert_eq!(&*decode::processes(reader.get_processes().unwrap()).unwrap(), &sent);
    }

    #[test]
    fn a_service_list_survives_the_wire() {
        let sent = [ServiceStats {
            name: "svc".into(),
            display_name: "Service".into(),
            pid: 9,
            state: ServiceState::PausePending,
            load_group: "group".into(),
            description: "does things".into(),
            image_path: "C:\\svc.exe".into(),
        }];
        let mut message = capnp::message::Builder::new_default();
        encode::services(&sent, message.init_root::<get_services_results::Builder>());
        let reader = message.get_root_as_reader::<get_services_results::Reader>().unwrap();
        assert_eq!(&*decode::services(reader.get_services().unwrap()).unwrap(), &sent);
    }

    #[test]
    fn metrics_survive_the_wire() {
        let sent = ProcessMetricsSnapshot {
            processes_etag: 42,
            metrics: vec![ProcessMetrics {
                pid: 100,
                cpu_percent: 12.5,
                working_set_kb: 1,
                private_bytes_kb: 2,
                peak_working_set_kb: 3,
                private_working_set_kb: 4,
                disk_read_bytes: 5,
                disk_write_bytes: 6,
                disk_read_iops: 7,
                disk_write_iops: 8,
                net_rx_bytes: 9,
                net_tx_bytes: 10,
            }],
        };
        let mut message = capnp::message::Builder::new_default();
        encode::process_metrics(&sent, message.init_root::<get_process_metrics_results::Builder>());
        let reader = message.get_root_as_reader::<get_process_metrics_results::Reader>().unwrap();
        assert_eq!(reader.get_processes_etag(), 42);
        assert_eq!(decode::metrics(reader.get_metrics().unwrap()), sent.metrics);
    }

    #[test]
    fn the_machine_survives_the_wire() {
        let sent = MachineStats {
            total_physical_kb: 1,
            available_physical_kb: 2,
            used_physical_kb: 3,
            cpu_percent: 4.5,
            cpu_max_mhz: 5,
            cpu_current_mhz: 6,
            cpu_interrupt_percent: 7.5,
            cpu_dpc_percent: 8.5,
            disk_read_bytes: 9,
            disk_write_bytes: 10,
            disk_read_iops: 11,
            disk_write_iops: 12,
            net_rx_bytes: 13,
            net_tx_bytes: 14,
        };
        let mut message = capnp::message::Builder::new_default();
        encode::machine(&sent, message.init_root::<machine_stats::Builder>());
        let reader = message.get_root_as_reader::<machine_stats::Reader>().unwrap();
        assert_eq!(decode::machine(reader), sent);
    }

    #[test]
    fn a_service_status_survives_the_wire() {
        let sent = ServiceStatus {
            state: ServiceState::StartPending,
            pid: 42,
            exit_code: 1066,
            service_exit_code: 7,
            checkpoint: 3,
            wait_hint_ms: 5000,
        };
        let mut message = capnp::message::Builder::new_default();
        encode::service_status(&sent, message.init_root::<service_status::Builder>());
        let reader = message.get_root_as_reader::<service_status::Reader>().unwrap();
        assert_eq!(decode::service_status(reader), sent);
    }

    #[test]
    fn every_priority_survives_the_wire() {
        for p in [
            ProcessPriority::Idle,
            ProcessPriority::BelowNormal,
            ProcessPriority::Normal,
            ProcessPriority::AboveNormal,
            ProcessPriority::High,
            ProcessPriority::Realtime,
        ] {
            assert_eq!(decode::priority(encode::priority(p)), p);
        }
    }
}
