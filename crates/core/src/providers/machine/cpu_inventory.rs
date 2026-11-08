use std::mem::{offset_of, size_of};
use std::sync::{Arc, OnceLock};

use crate::aligned::AlignedBuf;
use crate::bindings::{
    ALL_PROCESSOR_GROUPS, CACHE_RELATIONSHIP, CacheData, CacheInstruction, CacheUnified,
    ERROR_INSUFFICIENT_BUFFER, GROUP_AFFINITY, GetActiveProcessorCount, GetLastError,
    GetLogicalProcessorInformationEx, IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED,
    PROCESSOR_RELATIONSHIP, RelationCache, RelationProcessorCore, RelationProcessorPackage,
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};
use crate::sample::CpuInventory;

const MAX_TOPOLOGY_BYTES: usize = 1 << 20;
const HEADER: usize = offset_of!(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Anonymous);

pub fn read() -> Arc<CpuInventory> {
    cached().0.clone()
}

fn cached() -> &'static (Arc<CpuInventory>, Option<&'static str>) {
    static INVENTORY: OnceLock<(Arc<CpuInventory>, Option<&'static str>)> = OnceLock::new();
    INVENTORY.get_or_init(|| {
        let (inventory, source) = load();
        (Arc::new(inventory), source)
    })
}

pub fn context() -> serde_json::Value {
    let (inventory, source) = cached();
    serde_json::json!({"base_mhz": inventory.base_mhz, "base_mhz_source": source,
        "frequency_semantics": "nominal base frequency exposed by Intel CPUID; not current or maximum frequency"})
}

#[allow(unused_unsafe)]
fn load() -> (CpuInventory, Option<&'static str>) {
    let logical = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS as u16) };
    let caches = query(RelationCache).and_then(|bytes| cache_totals(&bytes));
    let (supported, hypervisor) = capabilities();
    let (supported, firmware) = virtualization(supported, hypervisor, || unsafe {
        IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED as u32).as_bool()
    });
    let mut brand_used = false;
    let base_mhz = base_frequency(|leaf| {
        brand_used |= (0x8000_0002..=0x8000_0004).contains(&leaf);
        unsafe { std::arch::x86_64::__cpuid(leaf) }
    });
    let source = base_mhz.map(|_| {
        if brand_used {
            "intel_brand_string"
        } else {
            "cpuid_16h"
        }
    });
    (
        CpuInventory {
            active_package_count: query(RelationProcessorPackage)
                .and_then(|bytes| processor_count(&bytes, RelationProcessorPackage)),
            physical_core_count: query(RelationProcessorCore)
                .and_then(|bytes| processor_count(&bytes, RelationProcessorCore)),
            logical_processor_count: (logical > 0).then_some(logical),
            l1_cache_bytes: caches.and_then(|totals| totals[0]),
            l2_cache_bytes: caches.and_then(|totals| totals[1]),
            l3_cache_bytes: caches.and_then(|totals| totals[2]),
            base_mhz,
            virtualization_hardware_supported: supported,
            virtualization_firmware_enabled: firmware,
            hypervisor_present: hypervisor,
        },
        source,
    )
}

fn base_frequency(mut cpuid: impl FnMut(u32) -> std::arch::x86_64::CpuidResult) -> Option<u32> {
    let basic = cpuid(0);
    if basic.ebx != u32::from_le_bytes(*b"Genu")
        || basic.edx != u32::from_le_bytes(*b"ineI")
        || basic.ecx != u32::from_le_bytes(*b"ntel")
    {
        return None;
    }
    if basic.eax >= 0x16 {
        let mhz = cpuid(0x16).eax & 0xffff;
        if mhz > 0 {
            return Some(mhz);
        }
    }
    if cpuid(0x8000_0000).eax < 0x8000_0004 {
        return None;
    }
    let mut brand = [0u8; 48];
    for (index, chunk) in brand.chunks_exact_mut(16).enumerate() {
        let value = cpuid(0x8000_0002 + index as u32);
        for (bytes, register) in chunk
            .chunks_exact_mut(4)
            .zip([value.eax, value.ebx, value.ecx, value.edx])
        {
            bytes.copy_from_slice(&register.to_le_bytes());
        }
    }
    brand_frequency(
        std::str::from_utf8(&brand)
            .ok()?
            .trim_end_matches('\0')
            .trim(),
    )
}

fn brand_frequency(brand: &str) -> Option<u32> {
    let frequency = brand.split_whitespace().last()?;
    let mhz = if let Some(value) = frequency.strip_suffix("GHz") {
        let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
        if whole.is_empty()
            || value.ends_with('.')
            || fraction.len() > 3
            || !whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit())
        {
            return None;
        }
        whole
            .parse::<u32>()
            .ok()?
            .checked_mul(1000)?
            .checked_add(if fraction.is_empty() {
                0
            } else {
                fraction.parse::<u32>().ok()? * 10u32.pow(3 - fraction.len() as u32)
            })?
    } else {
        let value = frequency.strip_suffix("MHz")?;
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        value.parse().ok()?
    };
    (mhz > 0).then_some(mhz)
}

fn virtualization(
    supported: Option<bool>,
    hypervisor: Option<bool>,
    firmware: impl FnOnce() -> bool,
) -> (Option<bool>, Option<bool>) {
    if hypervisor == Some(true) {
        return (None, None);
    }
    let enabled = (supported == Some(true) && hypervisor == Some(false)).then(firmware);
    (supported, enabled)
}

#[allow(unused_unsafe)]
fn capabilities() -> (Option<bool>, Option<bool>) {
    use std::arch::x86_64::__cpuid;
    let basic = unsafe { __cpuid(0) };
    if basic.eax < 1 {
        return (None, None);
    }
    let features = unsafe { __cpuid(1) };
    let hypervisor = features.ecx & (1 << 31) != 0;
    if hypervisor {
        return (None, Some(true));
    }
    let mut vendor = [0u8; 12];
    vendor[..4].copy_from_slice(&basic.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&basic.edx.to_le_bytes());
    vendor[8..].copy_from_slice(&basic.ecx.to_le_bytes());
    let supported = match &vendor {
        b"GenuineIntel" => Some(features.ecx & (1 << 5) != 0),
        b"AuthenticAMD" => {
            let extended = unsafe { __cpuid(0x8000_0000) };
            (extended.eax >= 0x8000_0001)
                .then(|| unsafe { __cpuid(0x8000_0001) }.ecx & (1 << 2) != 0)
        }
        _ => None,
    };
    (supported, Some(false))
}

fn query(relationship: i32) -> Option<Vec<u8>> {
    let mut length = 0u32;
    let first =
        unsafe { GetLogicalProcessorInformationEx(relationship, None, &mut length) }.as_bool();
    if first || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER as u32 {
        return None;
    }
    for _ in 0..3 {
        let size = length as usize;
        if !(HEADER..=MAX_TOPOLOGY_BYTES).contains(&size) {
            return None;
        }
        let mut bytes = AlignedBuf::zeroed(size);
        if unsafe {
            GetLogicalProcessorInformationEx(
                relationship,
                Some(bytes.as_mut_ptr().cast()),
                &mut length,
            )
        }
        .as_bool()
        {
            if length as usize > bytes.len() {
                return None;
            }
            return Some(
                unsafe { std::slice::from_raw_parts(bytes.as_ptr(), length as usize) }.to_vec(),
            );
        }
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER as u32 {
            return None;
        }
    }
    None
}

fn records(bytes: &[u8], relationship: i32) -> Option<Vec<&[u8]>> {
    let mut records = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if rest.len() < HEADER || rest.len() > MAX_TOPOLOGY_BYTES {
            return None;
        }
        let kind = i32::from_ne_bytes(rest.get(..4)?.try_into().ok()?);
        let size = u32::from_ne_bytes(rest.get(4..8)?.try_into().ok()?) as usize;
        if kind != relationship || size < HEADER {
            return None;
        }
        let record = rest.get(HEADER..size)?;
        records.push(record);
        rest = rest.get(size..)?;
    }
    (!records.is_empty()).then_some(records)
}

fn processor_count(bytes: &[u8], relationship: i32) -> Option<u32> {
    let records = records(bytes, relationship)?;
    for &record in &records {
        if record.len() < size_of::<PROCESSOR_RELATIONSHIP>() {
            return None;
        }
        let processor =
            unsafe { std::ptr::read_unaligned(record.as_ptr().cast::<PROCESSOR_RELATIONSHIP>()) };
        if processor.GroupCount == 0
            || offset_of!(PROCESSOR_RELATIONSHIP, GroupMask)
                + usize::from(processor.GroupCount) * size_of::<GROUP_AFFINITY>()
                > record.len()
        {
            return None;
        }
    }
    u32::try_from(records.len()).ok()
}

fn cache_totals(bytes: &[u8]) -> Option<[Option<u64>; 3]> {
    let mut totals = [None; 3];
    for record in records(bytes, RelationCache)? {
        if record.len() < size_of::<CACHE_RELATIONSHIP>() {
            return None;
        }
        let cache =
            unsafe { std::ptr::read_unaligned(record.as_ptr().cast::<CACHE_RELATIONSHIP>()) };
        let groups = usize::from(cache.GroupCount.max(1));
        if offset_of!(CACHE_RELATIONSHIP, Anonymous) + groups * size_of::<GROUP_AFFINITY>()
            > record.len()
        {
            return None;
        }
        if (1..=3).contains(&cache.Level)
            && [CacheUnified, CacheInstruction, CacheData].contains(&cache.Type)
        {
            let total = &mut totals[usize::from(cache.Level - 1)];
            *total = Some(
                total
                    .unwrap_or(0u64)
                    .checked_add(u64::from(cache.CacheSize))?,
            );
        }
    }
    Some(totals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_machine_inventory_is_cached() {
        let first = read();
        let second = read();
        assert!(Arc::ptr_eq(&first, &second));
        let logical = first
            .logical_processor_count
            .expect("active logical processors");
        assert!(logical > 0);
        for count in [first.active_package_count, first.physical_core_count]
            .into_iter()
            .flatten()
        {
            assert!(count > 0 && count <= logical);
        }
        assert!(first.base_mhz.is_none_or(|mhz| mhz > 0));
        println!(
            "cpu_inventory={}",
            serde_json::to_string(first.as_ref()).unwrap()
        );
    }

    #[test]
    fn base_frequency_uses_only_the_supported_intel_base_leaf_field() {
        use std::arch::x86_64::CpuidResult;
        let intel = CpuidResult {
            eax: 0x16,
            ebx: u32::from_le_bytes(*b"Genu"),
            edx: u32::from_le_bytes(*b"ineI"),
            ecx: u32::from_le_bytes(*b"ntel"),
        };
        assert_eq!(
            base_frequency(|leaf| match leaf {
                0 => intel,
                0x16 => CpuidResult {
                    eax: 0xffff_0b54,
                    ebx: 4300,
                    ecx: 100,
                    edx: 0
                },
                _ => panic!("unexpected CPUID leaf"),
            }),
            Some(2900)
        );
        assert_eq!(
            base_frequency(|leaf| if leaf == 0 {
                intel
            } else {
                CpuidResult {
                    eax: 0,
                    ebx: 4300,
                    ecx: 100,
                    edx: 0,
                }
            }),
            None
        );
        for basic in [CpuidResult { ebx: 0, ..intel }] {
            assert_eq!(
                base_frequency(|leaf| {
                    assert_eq!(leaf, 0);
                    basic
                }),
                None
            );
        }
    }

    #[test]
    fn intel_brand_frequency_is_nominal_and_missing_or_malformed_stays_unknown() {
        assert_eq!(
            brand_frequency("Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz"),
            Some(2900)
        );
        assert_eq!(brand_frequency("Intel CPU 1500MHz"), Some(1500));
        for brand in [
            "Intel CPU",
            "Intel CPU @ 0GHz",
            "Intel CPU @ -2.90GHz",
            "Intel CPU @ 2.9001GHz",
            "Intel CPU @ 2.9e0GHz",
            "Intel CPU @ 2.GHz",
        ] {
            assert_eq!(brand_frequency(brand), None);
        }
    }

    #[test]
    fn base_frequency_fallback_checks_extended_leaf_bounds_and_decodes_all_brand_registers() {
        use std::arch::x86_64::CpuidResult;
        let intel = CpuidResult {
            eax: 0x15,
            ebx: u32::from_le_bytes(*b"Genu"),
            edx: u32::from_le_bytes(*b"ineI"),
            ecx: u32::from_le_bytes(*b"ntel"),
        };
        let zero = CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
        assert_eq!(
            base_frequency(|leaf| match leaf {
                0 => intel,
                0x8000_0000 => CpuidResult {
                    eax: 0x8000_0003,
                    ..zero
                },
                _ => panic!("unsupported leaf was queried"),
            }),
            None
        );
        let mut brand = [0u8; 48];
        let text = b"Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz";
        brand[..text.len()].copy_from_slice(text);
        for maximum in [0x15, 0x16] {
            assert_eq!(
                base_frequency(|leaf| match leaf {
                    0 => CpuidResult {
                        eax: maximum,
                        ..intel
                    },
                    0x16 => zero,
                    0x8000_0000 => CpuidResult {
                        eax: 0x8000_0004,
                        ..zero
                    },
                    0x8000_0002..=0x8000_0004 => {
                        let at = (leaf - 0x8000_0002) as usize * 16;
                        let words: Vec<u32> = brand[at..at + 16]
                            .chunks_exact(4)
                            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                            .collect();
                        CpuidResult {
                            eax: words[0],
                            ebx: words[1],
                            ecx: words[2],
                            edx: words[3],
                        }
                    }
                    _ => panic!("unexpected leaf"),
                }),
                Some(2900)
            );
        }
    }

    #[test]
    fn hypervisor_or_absent_capability_never_claims_firmware_is_disabled() {
        assert_eq!(
            virtualization(Some(true), Some(true), || panic!("firmware is hidden")),
            (None, None)
        );
        assert_eq!(
            virtualization(Some(false), Some(false), || panic!("no capability")),
            (Some(false), None)
        );
        assert_eq!(
            virtualization(None, None, || panic!("unknown")),
            (None, None)
        );
        assert_eq!(
            virtualization(Some(true), Some(false), || false),
            (Some(true), Some(false))
        );
        assert_eq!(
            virtualization(Some(true), Some(false), || true),
            (Some(true), Some(true))
        );
    }

    fn header(kind: i32, payload: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER + payload];
        bytes[..4].copy_from_slice(&kind.to_ne_bytes());
        let size = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&size.to_ne_bytes());
        bytes
    }

    fn record(kind: i32, value: PROCESSOR_RELATIONSHIP, extra: usize) -> Vec<u8> {
        let mut bytes = header(kind, size_of::<PROCESSOR_RELATIONSHIP>() + extra);
        let at = HEADER + offset_of!(PROCESSOR_RELATIONSHIP, GroupCount);
        bytes[at..at + 2].copy_from_slice(&value.GroupCount.to_ne_bytes());
        bytes
    }

    fn cache_record(value: CACHE_RELATIONSHIP, extra: usize) -> Vec<u8> {
        let mut bytes = header(RelationCache, size_of::<CACHE_RELATIONSHIP>() + extra);
        bytes[HEADER + offset_of!(CACHE_RELATIONSHIP, Level)] = value.Level;
        let at = HEADER + offset_of!(CACHE_RELATIONSHIP, CacheSize);
        bytes[at..at + 4].copy_from_slice(&value.CacheSize.to_ne_bytes());
        let at = HEADER + offset_of!(CACHE_RELATIONSHIP, Type);
        bytes[at..at + 4].copy_from_slice(&value.Type.to_ne_bytes());
        let at = HEADER + offset_of!(CACHE_RELATIONSHIP, GroupCount);
        bytes[at..at + 2].copy_from_slice(&value.GroupCount.to_ne_bytes());
        bytes
    }

    #[test]
    fn packages_and_cores_count_records_not_smt_bits_or_processor_groups() {
        let processor = PROCESSOR_RELATIONSHIP {
            GroupCount: 2,
            ..Default::default()
        };
        let mut bytes = record(
            RelationProcessorPackage,
            processor,
            size_of::<GROUP_AFFINITY>(),
        );
        assert_eq!(processor_count(&bytes, RelationProcessorPackage), Some(1));
        bytes.extend_from_slice(&record(
            RelationProcessorPackage,
            processor,
            size_of::<GROUP_AFFINITY>(),
        ));
        assert_eq!(processor_count(&bytes, RelationProcessorPackage), Some(2));
        let core = record(
            RelationProcessorCore,
            processor,
            size_of::<GROUP_AFFINITY>(),
        );
        assert_eq!(processor_count(&core, RelationProcessorCore), Some(1));
    }

    #[test]
    fn split_l1_and_shared_multigroup_caches_are_summed_once_per_record() {
        let mut bytes = Vec::new();
        for (level, kind, size, groups) in [
            (1, CacheInstruction, 32 << 10, 1),
            (1, CacheData, 48 << 10, 1),
            (2, CacheUnified, 2 << 20, 1),
            (3, CacheUnified, 32 << 20, 2),
        ] {
            let cache = CACHE_RELATIONSHIP {
                Level: level,
                Type: kind,
                CacheSize: size,
                GroupCount: groups,
                ..Default::default()
            };
            bytes.extend_from_slice(&cache_record(
                cache,
                usize::from(groups - 1) * size_of::<GROUP_AFFINITY>(),
            ));
        }
        assert_eq!(
            cache_totals(&bytes),
            Some([Some(80 << 10), Some(2 << 20), Some(32 << 20)])
        );
        let only_l2 = cache_record(
            CACHE_RELATIONSHIP {
                Level: 2,
                Type: CacheUnified,
                CacheSize: 1024,
                GroupCount: 1,
                ..Default::default()
            },
            0,
        );
        assert_eq!(cache_totals(&only_l2), Some([None, Some(1024), None]));
    }

    #[test]
    fn truncated_or_inconsistent_relationship_records_are_unavailable() {
        assert_eq!(processor_count(&[], RelationProcessorCore), None);
        let processor = PROCESSOR_RELATIONSHIP {
            GroupCount: 2,
            ..Default::default()
        };
        let bytes = record(RelationProcessorCore, processor, 0);
        assert_eq!(processor_count(&bytes, RelationProcessorCore), None);
        assert_eq!(processor_count(&bytes, RelationProcessorPackage), None);
        for size in [0, 4, u32::MAX] {
            let mut malformed = bytes.clone();
            malformed[4..8].copy_from_slice(&size.to_ne_bytes());
            assert_eq!(processor_count(&malformed, RelationProcessorCore), None);
        }
        assert_eq!(cache_totals(&bytes[..5]), None);
    }
}
