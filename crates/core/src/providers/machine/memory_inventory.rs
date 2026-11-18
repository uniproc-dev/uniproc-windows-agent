use std::sync::{Arc, OnceLock};
use smbioslib::{SMBiosData, SMBiosMemoryDevice, SMBiosPhysicalMemoryArray, SMBiosStruct, MemorySize, MemorySizeExtended, MemorySpeed, MemorySpeedExtended};
use crate::bindings::GetPhysicallyInstalledSystemMemory;
use crate::sample::MemoryInventory;

pub(super) fn read(total_physical: u64) -> (Option<u64>, Option<Arc<MemoryInventory>>) {
    static INVENTORY: OnceLock<(Option<u64>, Arc<MemoryInventory>)> = OnceLock::new();
    let (installed, inventory) = INVENTORY.get_or_init(|| {
        let mut kib = 0u64;
        let installed = unsafe { GetPhysicallyInstalledSystemMemory(&mut kib) }.as_bool()
            .then(|| kib.checked_mul(1024)).flatten();
        let mut inventory = smbioslib::table_load_from_device().ok().map(|data| parse(&data)).unwrap_or_default();
        inventory.hardware_reserved = installed.and_then(|bytes| bytes.checked_sub(total_physical));
        (installed, Arc::new(inventory))
    });
    (*installed, Some(inventory.clone()))
}

fn uniform<T: Copy + Eq>(values: impl IntoIterator<Item = Option<T>>) -> Option<T> {
    let mut values = values.into_iter();
    let first = values.next()??;
    values.all(|value| value == Some(first)).then_some(first)
}

fn populated(device: &SMBiosMemoryDevice<'_>) -> Option<bool> {
    match device.size()? {
        MemorySize::NotInstalled => Some(false),
        MemorySize::Unknown => None,
        MemorySize::SeeExtendedSize => match device.extended_size()? {
            MemorySizeExtended::Megabytes(size) if size > 0 => Some(true),
            _ => None,
        },
        MemorySize::Kilobytes(size) | MemorySize::Megabytes(size) => Some(size > 0),
    }
}

fn speed(device: &SMBiosMemoryDevice<'_>) -> Option<u32> {
    match device.configured_memory_speed()? {
        MemorySpeed::MTs(speed) => Some(u32::from(speed)),
        MemorySpeed::SeeExtendedSpeed => match device.extended_configured_memory_speed()? {
            MemorySpeedExtended::MTs(speed) => Some(speed),
            _ => None,
        },
        MemorySpeed::Unknown => None,
    }
}

fn parse(data: &SMBiosData) -> MemoryInventory {
    let arrays: Vec<_> = data.defined_struct_iter::<SMBiosPhysicalMemoryArray>()
        .filter(|array| array.usage().is_some_and(|usage| usage.raw == 3)).collect();
    let mut inventory = MemoryInventory::default();
    if arrays.is_empty() {
        return inventory;
    }
    inventory.slots_total = arrays.iter().try_fold(0u32, |sum, array| sum.checked_add(u32::from(array.number_of_memory_devices()?)));
    let devices: Vec<_> = data.defined_struct_iter::<SMBiosMemoryDevice>()
        .filter(|device| arrays.iter().any(|array| device.physical_memory_array_handle() == Some(array.parts().header.handle()))).collect();
    if inventory.slots_total != u32::try_from(devices.len()).ok() || devices.iter().any(|device| populated(device).is_none()) {
        return inventory;
    }
    let used: Vec<_> = devices.iter().filter(|device| populated(device) == Some(true)).collect();
    inventory.slots_used = u32::try_from(used.len()).ok();
    inventory.memory_type = uniform(used.iter().map(|device| device.memory_type().map(|kind| kind.raw).filter(|raw| !matches!(raw, 0 | 2))));
    inventory.form_factor = uniform(used.iter().map(|device| device.form_factor().map(|form| form.raw).filter(|raw| !matches!(raw, 0 | 2))));
    inventory.speed_mt_s = uniform(used.iter().map(|device| speed(device)));
    inventory
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(size: u16, configured: u16) -> SMBiosData {
        let mut array = vec![0u8; 0x17];
        array[..4].copy_from_slice(&[16, 0x17, 1, 0]);
        array[5] = 3;
        array[13..15].copy_from_slice(&2u16.to_le_bytes());
        array.extend([0, 0]);
        for (handle, size) in [(2, size), (3, 0)] {
            let mut device = vec![0u8; 0x28];
            device[..4].copy_from_slice(&[17, 0x28, handle, 0]);
            device[4..6].copy_from_slice(&1u16.to_le_bytes());
            device[12..14].copy_from_slice(&size.to_le_bytes());
            device[14] = 9;
            device[18] = 26;
            device[21..23].copy_from_slice(&4800u16.to_le_bytes());
            device[32..34].copy_from_slice(&configured.to_le_bytes());
            array.extend(device);
            array.extend([0, 0]);
        }
        SMBiosData::from_vec_and_version(array, None)
    }

    #[test]
    fn configured_speed_and_populated_system_slots_come_from_smbios() {
        let inventory = parse(&table(8192, 3200));
        assert_eq!(inventory.slots_used, Some(1));
        assert_eq!(inventory.slots_total, Some(2));
        assert_eq!(inventory.memory_type, Some(26));
        assert_eq!(inventory.form_factor, Some(9));
        assert_eq!(inventory.speed_mt_s, Some(3200));
        assert_eq!(parse(&table(8192, 0)).speed_mt_s, None);
        assert_eq!(parse(&table(u16::MAX, 3200)).slots_used, None);
    }

    #[test]
    fn mixed_or_unknown_modules_do_not_invent_a_uniform_description() {
        assert_eq!(uniform([Some(3200u32), Some(3200)]), Some(3200));
        assert_eq!(uniform([Some(3200u32), Some(4800)]), None);
        assert_eq!(uniform([Some(3200u32), None]), None);
        assert_eq!(uniform::<u32>([]), None);
        assert_eq!(parse(&SMBiosData::from_vec_and_version(Vec::new(), None)), MemoryInventory::default());
    }
}
