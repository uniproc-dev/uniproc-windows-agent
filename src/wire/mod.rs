//! The `api` structs to and from the pipe's capnp messages; the client decodes what the service encodes.

pub mod decode;
pub mod encode;

use ogurpchik::auth::handshake::{Protocol, Version};
use uniproc_protocol::WINDOWS_PROTOCOL;

/// What both ends of the service's pipe present in the handshake: the windows schema's id and version.
pub const PROTOCOL: Protocol = Protocol::new(
    WINDOWS_PROTOCOL.id,
    WINDOWS_PROTOCOL.major,
    WINDOWS_PROTOCOL.minor,
    WINDOWS_PROTOCOL.patch,
);

/// Whether a peer reads a column's maximum as "no data for this row"
/// (windows.capnp 2.1); an older one would show it as a count.
pub fn takes_gaps(peer: Option<Version>) -> bool {
    peer.is_some_and(|v| (v.major, v.minor) >= (2, 1))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use uniproc_protocol::windows_capnp::{
        ProcessPriority as WirePriority, agent_listener, metric_spec, sampler, service_status,
        windows_agent,
    };
    use windows_agent::{get_process_states_results, get_processes_results, get_services_results};

    use super::{decode, encode};
    use crate::api::{
        Architecture, Changes, Columns, DpiAwareness, ExtendedCfg, IoPriority, Isolation, MachineCpu,
        MachineDisk, MachineMemory, MachineMetric, MachineMetrics, MachineNetwork, MachineProcessor, MachineSample,
        MetricSpec, Mitigations, ProcessInfo, ProcessMetric, ProcessMetrics, ProcessPriority,
        ProcessState, ProcessStates, Sample, ServiceState, ServiceStats, ServiceStatus,
        SignatureStatus, Snapshot, StackProtection, Tagged, UacVirtualization, Update,
    };

    fn process(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: 4,
            session_id: 1,
            name: "a.exe".into(),
            cmdline: ["a.exe".into(), "--flag".into()].into(),
            package_full_name: "Pkg_1.0_x64__abc".into(),
            package_relative_app_id: "App".into(),
            is_service: true,
            is_kernel_process: false,
            is_windows_process: true,
            signature: SignatureStatus::ThirdParty,
            image_path: "C:\\a.exe".into(),
            display_name: "A".into(),
            console_host_pid: 77,
            start_time: 133_000_000_000_000_000,
            sequence_number: pid as u64 * 3,
            user: "HOST\\user".into(),
            architecture: Architecture::X86,
            elevated: Some(true),
            uac_virtualization: UacVirtualization::Disabled,
            isolation: Isolation::AppContainer,
            dpi_awareness: DpiAwareness::PerMonitorV2,
            mitigations: Some(Mitigations {
                dep: Some(true),
                stack_protection: StackProtection::StrictAudit,
                extended_cfg: ExtendedCfg::Audit,
            }),
            publisher: "Publisher".into(),
        }
    }

    #[test]
    fn a_process_list_survives_the_wire() {
        let unknown = ProcessInfo {
            elevated: None,
            architecture: Architecture::Unknown,
            mitigations: None,
            ..process(300)
        };
        let sent = [process(100), process(200), unknown];
        let mut message = capnp::message::Builder::new_default();
        encode::processes(&sent, message.init_root::<get_processes_results::Builder>());
        let reader = message.get_root_as_reader::<get_processes_results::Reader>().unwrap();
        assert_eq!(&*decode::processes(reader.get_processes().unwrap()).unwrap(), &sent);
    }

    fn lists(etags: (u64, u64, u64), processes: Vec<ProcessInfo>, states: Vec<ProcessState>, services: &[&str]) -> Snapshot {
        Snapshot {
            services: Tagged {
                etag: etags.2,
                value: services
                    .iter()
                    .map(|&name| ServiceStats {
                        name: name.into(),
                        ..Default::default()
                    })
                    .collect(),
            },
            processes: Tagged {
                etag: etags.0,
                value: processes.into(),
            },
            states: Tagged {
                etag: etags.1,
                value: ProcessStates {
                    passport_etag: etags.0,
                    states: states.into(),
                },
            },
        }
    }

    fn state(pid: u32) -> ProcessState {
        ProcessState {
            pid,
            sequence_number: pid as u64 * 3,
            ..Default::default()
        }
    }

    fn pushed(before: Option<&Snapshot>, after: &Snapshot) -> (Update, (Snapshot, Changes)) {
        let update = Update {
            snapshot: after.clone(),
            sample: full_sample(),
            changes: crate::watch::changes(before, after),
        };
        let mut message = capnp::message::Builder::new_default();
        encode::update(&update, before, message.init_root::<agent_listener::update_params::Builder>()).unwrap();
        let reader = message.get_root_as_reader::<agent_listener::update_params::Reader>().unwrap();
        let applied = decode::lists(before, reader.get_lists().unwrap()).unwrap();
        (update, applied)
    }

    #[test]
    fn a_watch_builds_the_same_lists_and_changes_on_the_other_end() {
        let first = lists(
            (1, 1, 1),
            vec![process(100), process(200), process(300)],
            vec![state(100), state(200), state(300)],
            &["a"],
        );
        let (update, (snapshot, changes)) = pushed(None, &first);
        assert_eq!(snapshot, first);
        assert_eq!(changes, update.changes);
        assert!(changes.full);

        let renamed = ProcessInfo {
            display_name: "Two hundred".into(),
            ..process(200)
        };
        let second = lists(
            (2, 2, 1),
            vec![process(100), renamed, process(400)],
            vec![ProcessState { suspended: Some(true), ..state(100) }, state(200), state(400)],
            &["a"],
        );
        let (update, (snapshot, changes)) = pushed(Some(&first), &second);
        assert_eq!(snapshot, second);
        assert_eq!(changes, update.changes);
        assert_eq!(changes.passports, [(200, 600), (400, 1200)]);
        assert_eq!(changes.left, [(300, 900)]);
        assert_eq!(changes.states, [(100, 300), (400, 1200)]);
        assert!(!changes.full && !changes.services);

        let third = lists((2, 2, 7), second.processes.value.to_vec(), second.states.value.states.to_vec(), &["a", "b"]);
        let (_, (snapshot, changes)) = pushed(Some(&second), &third);
        assert_eq!(snapshot, third);
        assert!(changes.services && changes.passports.is_empty() && changes.states.is_empty());
    }

    #[test]
    fn a_delta_on_lists_the_client_does_not_hold_is_refused() {
        let first = lists((1, 1, 1), vec![process(100)], vec![state(100)], &[]);
        let second = lists((2, 2, 1), vec![process(100), process(200)], vec![state(100), state(200)], &[]);
        let update = Update {
            snapshot: second.clone(),
            sample: full_sample(),
            changes: crate::watch::changes(Some(&first), &second),
        };
        let mut message = capnp::message::Builder::new_default();
        encode::update(&update, Some(&first), message.init_root::<agent_listener::update_params::Builder>()).unwrap();
        let reader = message.get_root_as_reader::<agent_listener::update_params::Reader>().unwrap();
        let elsewhere = lists((9, 9, 1), vec![process(100)], vec![state(100)], &[]);
        assert!(decode::lists(Some(&elsewhere), reader.get_lists().unwrap()).is_err());
        assert!(decode::lists(None, reader.get_lists().unwrap()).is_err());
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
    fn process_states_survive_the_wire() {
        let sent = ProcessStates {
            passport_etag: 42,
            states: Arc::from([
                ProcessState {
                    pid: 100,
                    sequence_number: 300,
                    suspended: Some(false),
                    efficiency_mode: Some(true),
                    base_priority: Some(ProcessPriority::Idle),
                    power_throttling: Some(true),
                    job_object_id: 7,
                    io_priority: IoPriority::VeryLow,
                },
                ProcessState {
                    pid: 200,
                    ..ProcessState::default()
                },
            ]),
        };
        let mut message = capnp::message::Builder::new_default();
        encode::process_states(&sent, message.init_root::<get_process_states_results::Builder>());
        let reader = message.get_root_as_reader::<get_process_states_results::Reader>().unwrap();
        assert_eq!(reader.get_passport_etag(), 42);
        assert_eq!(decode::process_states(reader.get_states().unwrap()), sent.states);
    }

    fn spec(processes: impl Into<ProcessMetrics>, machine: impl Into<MachineMetrics>) -> MetricSpec {
        MetricSpec {
            interval: Duration::from_millis(1500),
            processes: processes.into(),
            machine: machine.into(),
        }
    }

    #[test]
    fn a_metric_spec_survives_the_wire() {
        for sent in [
            spec(ProcessMetrics::all(), MachineMetrics::all()),
            spec(ProcessMetric::PageFaults, MachineMetric::Disk),
            spec(ProcessMetrics::empty(), MachineMetrics::empty()),
        ] {
            let mut message = capnp::message::Builder::new_default();
            encode::metric_spec(&sent, message.init_root::<metric_spec::Builder>());
            let reader = message.get_root_as_reader::<metric_spec::Reader>().unwrap();
            assert_eq!(decode::metric_spec(reader).unwrap(), sent);
        }
    }

    fn full_sample() -> Sample {
        let rows = |base: u64| -> Option<Arc<[u64]>> { Some(Arc::from([base, base + 1])) };
        let rows32 = |base: u32| -> Option<Arc<[u32]>> { Some(Arc::from([base, base + 1])) };
        Sample {
            snapshot: 9,
            sampled_at: 123_456,
            period: Duration::from_millis(1500),
            wanted: spec(ProcessMetrics::all(), MachineMetrics::all()),
            passport_etag: 5,
            pids: Arc::from([4, 100]),
            sequence_numbers: Arc::from([1, 300]),
            columns: Columns {
                cpu_user_time: rows(10),
                cpu_kernel_time: rows(20),
                cpu_cycles: rows(30),
                working_set: rows(40),
                peak_working_set: rows(50),
                private_working_set: rows(60),
                commit: rows(70),
                paged_pool: rows(80),
                non_paged_pool: rows(90),
                page_faults: rows32(100),
                handles: rows32(110),
                threads: rows32(120),
                user_objects: rows32(130),
                gdi_objects: rows32(140),
                io_read_ops: rows(150),
                io_write_ops: rows(160),
                io_other_ops: rows(170),
                io_read_bytes: rows(180),
                io_write_bytes: rows(190),
                io_other_bytes: rows(200),
                disk_read_ops: rows(210),
                disk_write_ops: rows(220),
                disk_flush_ops: rows(230),
                disk_read_bytes: rows(240),
                disk_write_bytes: rows(250),
                net_rx_bytes: rows(260),
                net_tx_bytes: rows(270),
                virtual_size: rows(280),
                peak_virtual_size: rows(290),
                peak_commit: rows(300),
                peak_paged_pool: rows(310),
                peak_non_paged_pool: rows(320),
                hard_faults: rows32(330),
                peak_threads: rows32(340),
                context_switches: rows(350),
            },
            machine: MachineSample {
                cpu: Some(MachineCpu {
                    idle_time: 1,
                    kernel_time: 2,
                    user_time: 3,
                    interrupt_time: 4,
                    dpc_time: 5,
                    max_mhz: 6,
                    current_mhz: 7,
                }),
                memory: Some(MachineMemory {
                    total_physical: 8,
                    available_physical: 9,
                    commit_limit: 16,
                    committed: 17,
                }),
                disk: Some(MachineDisk {
                    read_ops: 10,
                    write_ops: 11,
                    read_bytes: 12,
                    write_bytes: 13,
                }),
                network: Some(MachineNetwork {
                    rx_bytes: 14,
                    tx_bytes: 15,
                }),
                processors: Some(Arc::from([
                    MachineProcessor {
                        idle_time: 18,
                        kernel_time: 19,
                        user_time: 20,
                        interrupt_time: 21,
                        dpc_time: 22,
                    },
                    MachineProcessor {
                        idle_time: 23,
                        kernel_time: 24,
                        user_time: 25,
                        interrupt_time: 26,
                        dpc_time: 27,
                    },
                ])),
            },
        }
    }

    fn round_trip(sent: &Sample) -> Sample {
        let mut message = capnp::message::Builder::new_default();
        encode::sample(sent, message.init_root::<sampler::sample_results::Builder>()).unwrap();
        let reader = message.get_root_as_reader::<sampler::sample_results::Reader>().unwrap();
        decode::sample(reader.get_processes().unwrap(), reader.get_machine().unwrap(), sent.wanted).unwrap()
    }

    #[test]
    fn a_sample_survives_the_wire() {
        let sent = full_sample();
        assert_eq!(round_trip(&sent), sent);
    }

    #[test]
    fn a_projected_sample_carries_only_its_own_metrics() {
        let full = full_sample();
        for wanted in [
            spec(ProcessMetric::PageFaults | ProcessMetric::NetTxBytes, MachineMetric::Memory),
            spec(ProcessMetrics::empty(), MachineMetric::Cpu | MachineMetric::Network),
            spec(ProcessMetric::Handles, MachineMetrics::empty()),
            spec(ProcessMetric::HardFaults | ProcessMetric::ContextSwitches, MachineMetric::Processors),
            spec(ProcessMetrics::empty(), MachineMetrics::empty()),
        ] {
            let sent = full.project(&wanted);
            assert_eq!(round_trip(&sent), sent);
        }
    }

    #[test]
    fn a_projection_without_process_metrics_has_no_rows() {
        let sent = full_sample().project(&spec(ProcessMetrics::empty(), MachineMetric::Cpu));
        assert!(sent.pids.is_empty() && sent.sequence_numbers.is_empty());
        assert_eq!(sent.columns, Columns::default());
        assert_eq!(sent.machine.cpu, full_sample().machine.cpu);
        assert_eq!(sent.machine.memory, None);
        assert_eq!(ProcessMetrics::empty(), sent.wanted.processes);
        assert_eq!(MachineMetrics::only(MachineMetric::Cpu), sent.wanted.machine);
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
    fn only_a_2_1_peer_takes_gaps() {
        let v = |major, minor| {
            Some(ogurpchik::auth::handshake::Version {
                major,
                minor,
                patch: 0,
            })
        };
        assert!(!super::takes_gaps(None));
        assert!(!super::takes_gaps(v(2, 0)));
        assert!(super::takes_gaps(v(2, 1)));
        assert!(super::takes_gaps(v(3, 0)));
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
            assert_eq!(decode::priority(Ok(encode::priority(p))), Some(p));
        }
        assert_eq!(decode::priority(Ok(WirePriority::Unknown)), None);
    }
}
