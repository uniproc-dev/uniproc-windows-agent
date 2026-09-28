use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use capnp::struct_list;
use uniproc_protocol::windows_capnp::{
    Architecture as WireArchitecture, DpiAwareness as WireDpi, ExtendedCfg as WireExtendedCfg,
    IoPriority as WireIoPriority, Isolation as WireIsolation, MachineMetric as WireMachineMetric,
    ProcessMetric as WireProcessMetric, ProcessPriority as WirePriority, ServiceState as WireServiceState,
    SignatureStatus as WireSignature, StackProtection as WireStackProtection, Toggle,
    UacVirtualization as WireUac, lists_update, machine_sample, metric_spec, process_columns,
    process_info, process_state, service_stats, service_status,
};

use crate::api::{
    Architecture, Changes, Columns, DpiAwareness, ExtendedCfg, IoPriority, Isolation, MachineCpu,
    MachineDisk, MachineMemory, MachineMetric, MachineNetwork, MachineProcessor, MachineSample, MetricSpec,
    Mitigations, ProcessInfo, ProcessMetric, ProcessPriority, ProcessState, ProcessStates, Sample,
    ServiceState, ServiceStats, ServiceStatus, SignatureStatus, Snapshot, StackProtection, Tagged,
    UacVirtualization,
};

type Wire<T> = Result<T, capnp::NotInSchema>;

fn text<T: for<'a> From<&'a str>>(reader: capnp::Result<capnp::text::Reader<'_>>) -> capnp::Result<T> {
    Ok(reader?.to_str()?.into())
}

fn signature(s: Wire<WireSignature>) -> SignatureStatus {
    match s {
        Ok(WireSignature::Unsigned) => SignatureStatus::Unsigned,
        Ok(WireSignature::Microsoft) => SignatureStatus::Microsoft,
        Ok(WireSignature::ThirdParty) => SignatureStatus::ThirdParty,
        Ok(WireSignature::Unknown) | Err(_) => SignatureStatus::Unknown,
    }
}

fn service_state(s: Wire<WireServiceState>) -> ServiceState {
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

/// `None` for `unknown` or a value this build does not know.
pub fn priority(p: Wire<WirePriority>) -> Option<ProcessPriority> {
    match p {
        Ok(WirePriority::Idle) => Some(ProcessPriority::Idle),
        Ok(WirePriority::BelowNormal) => Some(ProcessPriority::BelowNormal),
        Ok(WirePriority::Normal) => Some(ProcessPriority::Normal),
        Ok(WirePriority::AboveNormal) => Some(ProcessPriority::AboveNormal),
        Ok(WirePriority::High) => Some(ProcessPriority::High),
        Ok(WirePriority::Realtime) => Some(ProcessPriority::Realtime),
        Ok(WirePriority::Unknown) | Err(_) => None,
    }
}

fn toggle(t: Wire<Toggle>) -> Option<bool> {
    match t {
        Ok(Toggle::On) => Some(true),
        Ok(Toggle::Off) => Some(false),
        Ok(Toggle::Unknown) | Err(_) => None,
    }
}

fn architecture(a: Wire<WireArchitecture>) -> Architecture {
    match a {
        Ok(WireArchitecture::X86) => Architecture::X86,
        Ok(WireArchitecture::X64) => Architecture::X64,
        Ok(WireArchitecture::Arm) => Architecture::Arm,
        Ok(WireArchitecture::Arm64) => Architecture::Arm64,
        Ok(WireArchitecture::Arm64X86Compatible) => Architecture::Arm64X86Compatible,
        Ok(WireArchitecture::Arm64X64Compatible) => Architecture::Arm64X64Compatible,
        Ok(WireArchitecture::Unknown) | Err(_) => Architecture::Unknown,
    }
}

fn uac_virtualization(u: Wire<WireUac>) -> UacVirtualization {
    match u {
        Ok(WireUac::NotAllowed) => UacVirtualization::NotAllowed,
        Ok(WireUac::Disabled) => UacVirtualization::Disabled,
        Ok(WireUac::Enabled) => UacVirtualization::Enabled,
        Ok(WireUac::Unknown) | Err(_) => UacVirtualization::Unknown,
    }
}

fn isolation(i: Wire<WireIsolation>) -> Isolation {
    match i {
        Ok(WireIsolation::None) => Isolation::None,
        Ok(WireIsolation::AppContainer) => Isolation::AppContainer,
        Ok(WireIsolation::Uwp) => Isolation::Uwp,
        Ok(WireIsolation::Silo) => Isolation::Silo,
        Ok(WireIsolation::Unknown) | Err(_) => Isolation::Unknown,
    }
}

fn dpi_awareness(d: Wire<WireDpi>) -> DpiAwareness {
    match d {
        Ok(WireDpi::Unaware) => DpiAwareness::Unaware,
        Ok(WireDpi::System) => DpiAwareness::System,
        Ok(WireDpi::PerMonitor) => DpiAwareness::PerMonitor,
        Ok(WireDpi::PerMonitorV2) => DpiAwareness::PerMonitorV2,
        Ok(WireDpi::UnawareGdiScaled) => DpiAwareness::UnawareGdiScaled,
        Ok(WireDpi::Unknown) | Err(_) => DpiAwareness::Unknown,
    }
}

fn stack_protection(s: Wire<WireStackProtection>) -> StackProtection {
    match s {
        Ok(WireStackProtection::Off) => StackProtection::Off,
        Ok(WireStackProtection::Compatible) => StackProtection::Compatible,
        Ok(WireStackProtection::Strict) => StackProtection::Strict,
        Ok(WireStackProtection::CompatibleAudit) => StackProtection::CompatibleAudit,
        Ok(WireStackProtection::StrictAudit) => StackProtection::StrictAudit,
        Ok(WireStackProtection::Unknown) | Err(_) => StackProtection::Unknown,
    }
}

fn extended_cfg(e: Wire<WireExtendedCfg>) -> ExtendedCfg {
    match e {
        Ok(WireExtendedCfg::Off) => ExtendedCfg::Off,
        Ok(WireExtendedCfg::Audit) => ExtendedCfg::Audit,
        Ok(WireExtendedCfg::On) => ExtendedCfg::On,
        Ok(WireExtendedCfg::Unknown) | Err(_) => ExtendedCfg::Unknown,
    }
}

fn io_priority(p: Wire<WireIoPriority>) -> IoPriority {
    match p {
        Ok(WireIoPriority::VeryLow) => IoPriority::VeryLow,
        Ok(WireIoPriority::Low) => IoPriority::Low,
        Ok(WireIoPriority::Normal) => IoPriority::Normal,
        Ok(WireIoPriority::High) => IoPriority::High,
        Ok(WireIoPriority::Critical) => IoPriority::Critical,
        Ok(WireIoPriority::Unknown) | Err(_) => IoPriority::Unknown,
    }
}

fn process_metric(m: WireProcessMetric) -> ProcessMetric {
    match m {
        WireProcessMetric::CpuUserTime => ProcessMetric::CpuUserTime,
        WireProcessMetric::CpuKernelTime => ProcessMetric::CpuKernelTime,
        WireProcessMetric::CpuCycles => ProcessMetric::CpuCycles,
        WireProcessMetric::WorkingSet => ProcessMetric::WorkingSet,
        WireProcessMetric::PeakWorkingSet => ProcessMetric::PeakWorkingSet,
        WireProcessMetric::PrivateWorkingSet => ProcessMetric::PrivateWorkingSet,
        WireProcessMetric::Commit => ProcessMetric::Commit,
        WireProcessMetric::PagedPool => ProcessMetric::PagedPool,
        WireProcessMetric::NonPagedPool => ProcessMetric::NonPagedPool,
        WireProcessMetric::PageFaults => ProcessMetric::PageFaults,
        WireProcessMetric::Handles => ProcessMetric::Handles,
        WireProcessMetric::Threads => ProcessMetric::Threads,
        WireProcessMetric::UserObjects => ProcessMetric::UserObjects,
        WireProcessMetric::GdiObjects => ProcessMetric::GdiObjects,
        WireProcessMetric::IoReadOps => ProcessMetric::IoReadOps,
        WireProcessMetric::IoWriteOps => ProcessMetric::IoWriteOps,
        WireProcessMetric::IoOtherOps => ProcessMetric::IoOtherOps,
        WireProcessMetric::IoReadBytes => ProcessMetric::IoReadBytes,
        WireProcessMetric::IoWriteBytes => ProcessMetric::IoWriteBytes,
        WireProcessMetric::IoOtherBytes => ProcessMetric::IoOtherBytes,
        WireProcessMetric::DiskReadOps => ProcessMetric::DiskReadOps,
        WireProcessMetric::DiskWriteOps => ProcessMetric::DiskWriteOps,
        WireProcessMetric::DiskFlushOps => ProcessMetric::DiskFlushOps,
        WireProcessMetric::DiskReadBytes => ProcessMetric::DiskReadBytes,
        WireProcessMetric::DiskWriteBytes => ProcessMetric::DiskWriteBytes,
        WireProcessMetric::NetRxBytes => ProcessMetric::NetRxBytes,
        WireProcessMetric::NetTxBytes => ProcessMetric::NetTxBytes,
        WireProcessMetric::VirtualSize => ProcessMetric::VirtualSize,
        WireProcessMetric::PeakVirtualSize => ProcessMetric::PeakVirtualSize,
        WireProcessMetric::PeakCommit => ProcessMetric::PeakCommit,
        WireProcessMetric::PeakPagedPool => ProcessMetric::PeakPagedPool,
        WireProcessMetric::PeakNonPagedPool => ProcessMetric::PeakNonPagedPool,
        WireProcessMetric::HardFaults => ProcessMetric::HardFaults,
        WireProcessMetric::PeakThreads => ProcessMetric::PeakThreads,
        WireProcessMetric::ContextSwitches => ProcessMetric::ContextSwitches,
    }
}

fn machine_metric(m: WireMachineMetric) -> MachineMetric {
    match m {
        WireMachineMetric::Cpu => MachineMetric::Cpu,
        WireMachineMetric::Memory => MachineMetric::Memory,
        WireMachineMetric::Disk => MachineMetric::Disk,
        WireMachineMetric::Network => MachineMetric::Network,
        WireMachineMetric::Processors => MachineMetric::Processors,
    }
}

pub fn service_status(s: service_status::Reader<'_>) -> ServiceStatus {
    ServiceStatus {
        state: service_state(s.get_state()),
        pid: s.get_pid(),
        exit_code: s.get_exit_code(),
        service_exit_code: s.get_service_exit_code(),
        checkpoint: s.get_checkpoint(),
        wait_hint_ms: s.get_wait_hint_ms(),
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
                start_time: p.get_start_time(),
                sequence_number: p.get_sequence_number(),
                user: text(p.get_user())?,
                architecture: architecture(p.get_architecture()),
                elevated: toggle(p.get_elevated()),
                uac_virtualization: uac_virtualization(p.get_uac_virtualization()),
                isolation: isolation(p.get_isolation()),
                dpi_awareness: dpi_awareness(p.get_dpi_awareness()),
                mitigations: if p.has_mitigations() {
                    let m = p.get_mitigations()?;
                    Some(Mitigations {
                        dep: toggle(m.get_dep()),
                        stack_protection: stack_protection(m.get_stack_protection()),
                        extended_cfg: extended_cfg(m.get_extended_cfg()),
                    })
                } else {
                    None
                },
                publisher: text(p.get_publisher())?,
            })
        })
        .collect()
}

pub fn process_states(list: struct_list::Reader<'_, process_state::Owned>) -> Arc<[ProcessState]> {
    list.iter()
        .map(|s| ProcessState {
            pid: s.get_pid(),
            sequence_number: s.get_sequence_number(),
            suspended: toggle(s.get_suspended()),
            efficiency_mode: toggle(s.get_efficiency_mode()),
            base_priority: priority(s.get_base_priority()),
            power_throttling: toggle(s.get_power_throttling()),
            job_object_id: s.get_job_object_id(),
            io_priority: io_priority(s.get_io_priority()),
        })
        .collect()
}

/// The lists after one watch update, applied to `before`, which the previous
/// updates built, and what moved in them. Fails on a delta that does not
/// apply to what `before` holds.
pub fn lists(before: Option<&Snapshot>, lists: lists_update::Reader<'_>) -> capnp::Result<(Snapshot, Changes)> {
    let mut changes = Changes {
        full: before.is_none(),
        ..Changes::default()
    };
    let passport_etag = lists.get_passport_etag();

    let processes = match lists.get_passports().which()? {
        lists_update::passports::Unchanged(()) => held(before, |s| &s.processes)?.value.clone(),
        lists_update::passports::Full(list) => {
            let list = processes(list?)?;
            changes.passports = list.iter().map(|p| (p.pid, p.sequence_number)).collect();
            list
        }
        lists_update::passports::Delta(delta) => {
            let delta = delta?;
            let before = based(held(before, |s| &s.processes)?, delta.get_base_etag())?;
            let left: HashSet<u64> = delta.get_left()?.iter().collect();
            let upserted = processes(delta.get_upserted()?)?;
            changes.left = keys(before.value.iter().filter(|p| left.contains(&p.sequence_number)), |p| (p.pid, p.sequence_number));
            changes.passports = keys(upserted.iter(), |p| (p.pid, p.sequence_number));
            merge(&before.value, &left, &upserted, |p| (p.pid, p.sequence_number))
        }
    };

    let states = match lists.get_states().which()? {
        lists_update::states::Unchanged(()) => held(before, |s| &s.states)?.value.states.clone(),
        lists_update::states::Full(list) => {
            let list = process_states(list?);
            changes.states = keys(list.iter(), |s| (s.pid, s.sequence_number));
            list
        }
        lists_update::states::Delta(delta) => {
            let delta = delta?;
            let before = based(held(before, |s| &s.states)?, delta.get_base_etag())?;
            let left: HashSet<u64> = delta.get_left()?.iter().collect();
            let upserted = process_states(delta.get_upserted()?);
            changes.states = keys(upserted.iter(), |s| (s.pid, s.sequence_number));
            merge(&before.value.states, &left, &upserted, |s| (s.pid, s.sequence_number))
        }
    };

    let services = match lists.get_services().which()? {
        lists_update::services::Unchanged(()) => held(before, |s| &s.services)?.value.clone(),
        lists_update::services::Full(list) => {
            changes.services = true;
            services(list?)?
        }
    };

    let snapshot = Snapshot {
        services: Tagged {
            etag: lists.get_services_etag(),
            value: services,
        },
        processes: Tagged {
            etag: passport_etag,
            value: processes,
        },
        states: Tagged {
            etag: lists.get_states_etag(),
            value: ProcessStates { passport_etag, states },
        },
    };
    Ok((snapshot, changes))
}

fn held<'a, T>(before: Option<&'a Snapshot>, list: impl Fn(&'a Snapshot) -> &'a Tagged<T>) -> capnp::Result<&'a Tagged<T>> {
    before
        .map(list)
        .ok_or_else(|| capnp::Error::failed("an update refers to lists that never came".into()))
}

fn based<T>(held: &Tagged<T>, base: u64) -> capnp::Result<&Tagged<T>> {
    if held.etag == base {
        Ok(held)
    } else {
        Err(capnp::Error::failed(format!("a delta on {base:#x} to lists held under {:#x}", held.etag)))
    }
}

fn keys<'a, T: 'a>(rows: impl Iterator<Item = &'a T>, key: impl Fn(&T) -> (u32, u64)) -> Vec<(u32, u64)> {
    rows.map(key).collect()
}

/// `before` without the rows `left` names, with `upserted` in place of
/// the rows under their pids; ordered by pid.
fn merge<T: Clone>(before: &[T], left: &HashSet<u64>, upserted: &[T], key: impl Fn(&T) -> (u32, u64)) -> Arc<[T]> {
    let replaced: HashSet<u32> = upserted.iter().map(|row| key(row).0).collect();
    let mut rows: Vec<T> = before
        .iter()
        .filter(|row| {
            let (pid, sequence_number) = key(row);
            !left.contains(&sequence_number) && !replaced.contains(&pid)
        })
        .chain(upserted)
        .cloned()
        .collect();
    rows.sort_by_key(|row| key(row).0);
    rows.into()
}

/// Metrics this build does not know are left out.
pub fn metric_spec(spec: metric_spec::Reader<'_>) -> capnp::Result<MetricSpec> {
    Ok(MetricSpec {
        interval: Duration::from_millis(spec.get_interval_ms() as u64),
        processes: spec
            .get_processes()?
            .iter()
            .filter_map(Result::ok)
            .map(process_metric)
            .collect(),
        machine: spec
            .get_machine()?
            .iter()
            .filter_map(Result::ok)
            .map(machine_metric)
            .collect(),
    })
}

macro_rules! columns {
    ($reader:ident, $($field:ident => ($has:ident, $get:ident),)*) => {
        Columns {
            $($field: if $reader.$has() {
                Some($reader.$get()?.iter().collect())
            } else {
                None
            },)*
        }
    };
}

/// A sample as the agent sent it, for a subscription that asked for `wanted`.
pub fn sample(
    processes: process_columns::Reader<'_>,
    machine: machine_sample::Reader<'_>,
    wanted: MetricSpec,
) -> capnp::Result<Sample> {
    let p = processes;
    Ok(Sample {
        snapshot: p.get_snapshot(),
        sampled_at: p.get_sampled_at(),
        period: wanted.period(),
        wanted,
        passport_etag: p.get_passport_etag(),
        pids: p.get_pids()?.iter().collect(),
        sequence_numbers: p.get_sequence_numbers()?.iter().collect(),
        columns: columns!(p,
            cpu_user_time => (has_cpu_user_time, get_cpu_user_time),
            cpu_kernel_time => (has_cpu_kernel_time, get_cpu_kernel_time),
            cpu_cycles => (has_cpu_cycles, get_cpu_cycles),
            working_set => (has_working_set, get_working_set),
            peak_working_set => (has_peak_working_set, get_peak_working_set),
            private_working_set => (has_private_working_set, get_private_working_set),
            commit => (has_commit, get_commit),
            paged_pool => (has_paged_pool, get_paged_pool),
            non_paged_pool => (has_non_paged_pool, get_non_paged_pool),
            page_faults => (has_page_faults, get_page_faults),
            handles => (has_handles, get_handles),
            threads => (has_threads, get_threads),
            user_objects => (has_user_objects, get_user_objects),
            gdi_objects => (has_gdi_objects, get_gdi_objects),
            io_read_ops => (has_io_read_ops, get_io_read_ops),
            io_write_ops => (has_io_write_ops, get_io_write_ops),
            io_other_ops => (has_io_other_ops, get_io_other_ops),
            io_read_bytes => (has_io_read_bytes, get_io_read_bytes),
            io_write_bytes => (has_io_write_bytes, get_io_write_bytes),
            io_other_bytes => (has_io_other_bytes, get_io_other_bytes),
            disk_read_ops => (has_disk_read_ops, get_disk_read_ops),
            disk_write_ops => (has_disk_write_ops, get_disk_write_ops),
            disk_flush_ops => (has_disk_flush_ops, get_disk_flush_ops),
            disk_read_bytes => (has_disk_read_bytes, get_disk_read_bytes),
            disk_write_bytes => (has_disk_write_bytes, get_disk_write_bytes),
            net_rx_bytes => (has_net_rx_bytes, get_net_rx_bytes),
            net_tx_bytes => (has_net_tx_bytes, get_net_tx_bytes),
            virtual_size => (has_virtual_size, get_virtual_size),
            peak_virtual_size => (has_peak_virtual_size, get_peak_virtual_size),
            peak_commit => (has_peak_commit, get_peak_commit),
            peak_paged_pool => (has_peak_paged_pool, get_peak_paged_pool),
            peak_non_paged_pool => (has_peak_non_paged_pool, get_peak_non_paged_pool),
            hard_faults => (has_hard_faults, get_hard_faults),
            peak_threads => (has_peak_threads, get_peak_threads),
            context_switches => (has_context_switches, get_context_switches),
        ),
        machine: machine_groups(machine)?,
    })
}

fn machine_groups(m: machine_sample::Reader<'_>) -> capnp::Result<MachineSample> {
    Ok(MachineSample {
        cpu: if m.has_cpu() {
            let c = m.get_cpu()?;
            Some(MachineCpu {
                idle_time: c.get_idle_time(),
                kernel_time: c.get_kernel_time(),
                user_time: c.get_user_time(),
                interrupt_time: c.get_interrupt_time(),
                dpc_time: c.get_dpc_time(),
                max_mhz: c.get_max_mhz(),
                current_mhz: c.get_current_mhz(),
            })
        } else {
            None
        },
        memory: if m.has_memory() {
            let mem = m.get_memory()?;
            Some(MachineMemory {
                total_physical: mem.get_total_physical(),
                available_physical: mem.get_available_physical(),
                commit_limit: mem.get_commit_limit(),
                committed: mem.get_committed(),
            })
        } else {
            None
        },
        disk: if m.has_disk() {
            let d = m.get_disk()?;
            Some(MachineDisk {
                read_ops: d.get_read_ops(),
                write_ops: d.get_write_ops(),
                read_bytes: d.get_read_bytes(),
                write_bytes: d.get_write_bytes(),
            })
        } else {
            None
        },
        network: if m.has_network() {
            let n = m.get_network()?;
            Some(MachineNetwork {
                rx_bytes: n.get_rx_bytes(),
                tx_bytes: n.get_tx_bytes(),
            })
        } else {
            None
        },
        processors: if m.has_processors() {
            Some(
                m.get_processors()?
                    .iter()
                    .map(|p| MachineProcessor {
                        idle_time: p.get_idle_time(),
                        kernel_time: p.get_kernel_time(),
                        user_time: p.get_user_time(),
                        interrupt_time: p.get_interrupt_time(),
                        dpc_time: p.get_dpc_time(),
                    })
                    .collect(),
            )
        } else {
            None
        },
    })
}
