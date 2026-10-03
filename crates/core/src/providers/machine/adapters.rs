//! The network adapters that are up, with their link speeds and counters.
//!
//! The interface table with counters costs about 9 ms on a machine whose
//! adapters carry filter stacks (WFP, Npcap, QoS), each layer a row of its
//! own. So the adapters are chosen from the table without counters, about
//! 1 ms, once a round, and only the chosen ones are read every tick.

use std::sync::Arc;
use std::time::Instant;

use crate::bindings::{
    FreeMibTable, GetIfEntry2, GetIfTable2Ex, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IfOperStatusUp,
    MIB_IF_ROW2, MibIfTableNormalWithoutStatistics, PMIB_IF_TABLE2,
};

use crate::probes::PROBE_ROUND;
use crate::sample::NetworkAdapter;

const HARDWARE_INTERFACE: u8 = 1;
const FILTER_INTERFACE: u8 = 1 << 1;
const LINK_SPEED_UNKNOWN: u64 = u64::MAX;

/// The adapters chosen at the last listing, read again every tick.
#[derive(Default)]
pub struct NetworkAdapters {
    chosen: Vec<u64>,
    listed: Option<Instant>,
}

impl NetworkAdapters {
    /// The chosen adapters as they are now; lists them again once a round,
    /// and at the next read when one went down or away.
    #[tracing::instrument(name = "network adapters", level = "debug", skip_all)]
    pub fn read(&mut self) -> Arc<[NetworkAdapter]> {
        if self.listed.is_none_or(|at| at.elapsed() >= PROBE_ROUND) {
            self.list();
        }
        let mut adapters = Vec::with_capacity(self.chosen.len());
        for &luid in &self.chosen {
            let mut row = MIB_IF_ROW2::default();
            row.InterfaceLuid.Value = luid;
            if unsafe { GetIfEntry2(&mut row) }.0 < 0 || !counted(&row) {
                self.listed = None;
                continue;
            }
            adapters.push(adapter(&row));
        }
        adapters.into()
    }

    fn list(&mut self) {
        self.listed = Some(Instant::now());
        let mut table: PMIB_IF_TABLE2 = std::ptr::null_mut();
        let status = unsafe { GetIfTable2Ex(MibIfTableNormalWithoutStatistics, &mut table) };
        if status.0 < 0 || table.is_null() {
            tracing::warn!(status = format_args!("{:#x}", status.0), "could not list the network adapters");
            return;
        }
        let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
        self.chosen.clear();
        self.chosen
            .extend(rows.iter().filter(|row| counted(row)).map(|row| unsafe { row.InterfaceLuid.Value }));
        unsafe { FreeMibTable(table.cast()) };
    }
}

fn flags(row: &MIB_IF_ROW2) -> u8 {
    unsafe { *(&raw const row.InterfaceAndOperStatusFlags).cast::<u8>() }
}

/// Up, a link of its own rather than a filter layer on one, and neither the
/// loopback nor a tunnel; a WAN miniport has no link speed.
fn counted(row: &MIB_IF_ROW2) -> bool {
    let kind = row.Type.0 as i32;
    row.OperStatus == IfOperStatusUp
        && flags(row) & FILTER_INTERFACE == 0
        && kind != IF_TYPE_SOFTWARE_LOOPBACK
        && kind != IF_TYPE_TUNNEL
        && (row.ReceiveLinkSpeed != 0 || row.TransmitLinkSpeed != 0)
}

fn adapter(row: &MIB_IF_ROW2) -> NetworkAdapter {
    let speed = |bits: u64| if bits == LINK_SPEED_UNKNOWN { 0 } else { bits };
    NetworkAdapter {
        luid: unsafe { row.InterfaceLuid.Value },
        name: wide(&row.Alias).into(),
        description: wide(&row.Description).into(),
        if_type: row.Type.0,
        hardware: flags(row) & HARDWARE_INTERFACE != 0,
        receive_link_speed: speed(row.ReceiveLinkSpeed),
        transmit_link_speed: speed(row.TransmitLinkSpeed),
        rx_bytes: row.InOctets,
        tx_bytes: row.OutOctets,
    }
}

fn wide(units: &[u16]) -> String {
    let end = units.iter().position(|&unit| unit == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_adapters_that_are_up_come_without_their_filter_layers() {
        let mut adapters = NetworkAdapters::default();
        let read = adapters.read();
        for adapter in read.iter() {
            assert!(!adapter.name.is_empty(), "{adapter:?}");
            assert!(!adapter.description.contains("LightWeight Filter"), "{}", adapter.description);
            assert!(!adapter.description.contains("Loopback Interface"), "{}", adapter.description);
            assert_ne!(adapter.if_type, 131, "no tunnels");
        }
        let mut luids: Vec<u64> = read.iter().map(|a| a.luid).collect();
        luids.dedup();
        assert_eq!(luids.len(), read.len(), "an adapter once");
        if let Some(nic) = read.iter().find(|a| a.hardware) {
            assert!(nic.rx_bytes > 0 && nic.receive_link_speed > 0, "{nic:?}");
        }
    }

    #[test]
    fn counters_only_grow_between_reads() {
        let mut adapters = NetworkAdapters::default();
        let first = adapters.read();
        let second = adapters.read();
        for a in first.iter() {
            if let Some(b) = second.iter().find(|b| b.luid == a.luid) {
                assert!(b.rx_bytes >= a.rx_bytes && b.tx_bytes >= a.tx_bytes);
            }
        }
    }
}
