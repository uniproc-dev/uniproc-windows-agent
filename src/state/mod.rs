pub mod events;
pub mod process;

use std::collections::HashSet;

use crate::state::events::{MachineSnapshot, StateChange};
use crate::state::process::{ProcessEntry, ProcessTable};

/// Machine-wide cumulative counters. Monotonic by construction: they only
/// accumulate ETW events and are not affected by process exits.
#[derive(Default, Debug, Clone)]
pub struct MachineTotals {
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_ops: u64,
    pub disk_write_ops: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

pub struct SystemState {
    processes: ProcessTable,
    machine: Option<MachineSnapshot>,
    machine_totals: MachineTotals,
    service_pids: HashSet<u32>,
    services: Vec<crate::providers::utils::ServiceInfo>,
    epoch: u32,
    services_generation: u32,
    service_pids_generation: u32,
}

fn random_epoch() -> u32 {
    loop {
        match getrandom::u32() {
            Ok(0) => continue,
            Ok(epoch) => return epoch,
            Err(_) => {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.subsec_nanos());
                return nanos | 1;
            }
        }
    }
}

fn etag(epoch: u32, generation: u32) -> u64 {
    (epoch as u64) << 32 | generation as u64
}

impl SystemState {
    pub fn new() -> Self {
        Self {
            processes: ProcessTable::new(),
            machine: None,
            machine_totals: MachineTotals::default(),
            service_pids: HashSet::new(),
            services: Vec::new(),
            epoch: random_epoch(),
            services_generation: 0,
            service_pids_generation: 0,
        }
    }

    pub fn apply(&mut self, change: StateChange) {
        match &change {
            StateChange::Machine(snap) => {
                let attributable =
                    (snap.cpu_percent - snap.cpu_interrupt_percent - snap.cpu_dpc_percent).max(0.0);
                self.machine = Some(MachineSnapshot::clone(snap));
                self.processes.fold_samples(attributable);
            }
            StateChange::ServicesSnapshot(services) => {
                let service_pids: HashSet<u32> = services
                    .iter()
                    .map(|s| s.pid)
                    .filter(|&pid| pid != 0)
                    .collect();
                if service_pids != self.service_pids {
                    self.service_pids = service_pids;
                    self.service_pids_generation = self.service_pids_generation.wrapping_add(1);
                }
                if *services != self.services {
                    self.services = services.clone();
                    self.services_generation = self.services_generation.wrapping_add(1);
                }
            }
            StateChange::Disk(deltas) => {
                for d in deltas.values() {
                    self.machine_totals.disk_read_bytes += d.read_bytes;
                    self.machine_totals.disk_read_ops += d.read_ops;
                    self.machine_totals.disk_write_bytes += d.write_bytes;
                    self.machine_totals.disk_write_ops += d.write_ops;
                }
            }
            StateChange::Network(deltas) => {
                for d in deltas.values() {
                    self.machine_totals.net_rx_bytes += d.rx_bytes;
                    self.machine_totals.net_tx_bytes += d.tx_bytes;
                }
            }
            _ => {}
        }
        self.processes.apply(change);
    }

    /// Tag of what getProcesses returns: moves with every passport change
    /// and with every change to which pids are services. Never zero.
    pub fn processes_etag(&self) -> u64 {
        etag(
            self.epoch,
            self.processes
                .passport_generation()
                .wrapping_add(self.service_pids_generation),
        )
    }

    /// Tag of what getServices returns. Never zero.
    pub fn services_etag(&self) -> u64 {
        etag(self.epoch, self.services_generation)
    }

    pub fn machine(&self) -> Option<&MachineSnapshot> {
        self.machine.as_ref()
    }

    pub fn sample_counts(&self) -> (u64, u64, u64) {
        self.processes.sample_counts()
    }

    pub fn machine_totals(&self) -> &MachineTotals {
        &self.machine_totals
    }

    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// By-reference view for report building: no per-request cloning of the
    /// whole table. Dynamic flags are resolved per entry by the caller.
    pub fn entries(&self) -> impl Iterator<Item = &ProcessEntry> {
        self.processes.entries()
    }

    pub fn is_service(&self, pid: u32) -> bool {
        self.service_pids.contains(&pid)
    }

    pub fn services(&self) -> &[crate::providers::utils::ServiceInfo] {
        &self.services
    }
}

impl Default for SystemState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::utils::ServiceInfo;
    use crate::state::events::ProcessStarted;

    fn service(name: &str, pid: u32) -> ServiceInfo {
        ServiceInfo {
            name: name.to_string(),
            pid,
            ..Default::default()
        }
    }

    fn started(pid: u32) -> StateChange {
        StateChange::ProcessStarted(Box::new(ProcessStarted {
            pid,
            parent_pid: 0,
            session_id: 0,
            image_name: format!("p{pid}.exe"),
            command_line: Vec::new(),
            package_full_name: String::new(),
            package_relative_app_id: String::new(),
            is_kernel_process: false,
        }))
    }

    #[test]
    fn a_tag_is_never_zero() {
        let s = SystemState::new();
        assert_ne!(s.processes_etag(), 0);
        assert_ne!(s.services_etag(), 0);
    }

    #[test]
    fn two_runs_start_from_different_tags() {
        assert_ne!(
            SystemState::new().processes_etag(),
            SystemState::new().processes_etag(),
            "a restarted agent must not hand out a tag a client still holds"
        );
    }

    #[test]
    fn the_same_inventory_again_keeps_both_tags() {
        let mut s = SystemState::new();
        s.apply(StateChange::ServicesSnapshot(vec![service("a", 10)]));
        let (processes, services) = (s.processes_etag(), s.services_etag());

        s.apply(StateChange::ServicesSnapshot(vec![service("a", 10)]));
        assert_eq!(s.processes_etag(), processes);
        assert_eq!(s.services_etag(), services);
    }

    #[test]
    fn a_service_changing_pid_moves_the_processes_tag_too() {
        let mut s = SystemState::new();
        s.apply(StateChange::ServicesSnapshot(vec![service("a", 10)]));
        let (processes, services) = (s.processes_etag(), s.services_etag());

        s.apply(StateChange::ServicesSnapshot(vec![service("a", 20)]));
        assert_ne!(s.services_etag(), services);
        assert_ne!(s.processes_etag(), processes, "isService is derived from the inventory");
    }

    #[test]
    fn a_description_change_leaves_the_processes_tag() {
        let mut s = SystemState::new();
        s.apply(StateChange::ServicesSnapshot(vec![service("a", 10)]));
        let processes = s.processes_etag();

        let mut described = service("a", 10);
        described.description = "now described".to_string();
        s.apply(StateChange::ServicesSnapshot(vec![described]));
        assert_eq!(s.processes_etag(), processes);
    }

    #[test]
    fn a_process_starting_moves_only_the_processes_tag() {
        let mut s = SystemState::new();
        let (processes, services) = (s.processes_etag(), s.services_etag());
        s.apply(started(100));
        assert_ne!(s.processes_etag(), processes);
        assert_eq!(s.services_etag(), services);
    }
}
