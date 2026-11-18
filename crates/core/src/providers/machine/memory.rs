use ntapi::ntexapi::{NtQuerySystemInformation, SystemMemoryListInformation, SYSTEM_MEMORY_LIST_INFORMATION};
use crate::bindings::{GetPerformanceInfo, GetProcessMemoryInfo, PERFORMANCE_INFORMATION, PROCESS_MEMORY_COUNTERS, PROCESS_QUERY_LIMITED_INFORMATION};
use crate::sample::{MachineMemory, MemoryDetails};

pub(super) fn read() -> Option<MachineMemory> {
    let mut memory = super::sample::physical_memory()?;
    let mut performance = PERFORMANCE_INFORMATION {
        cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
        ..Default::default()
    };
    let performance = unsafe { GetPerformanceInfo(&mut performance, size_of::<PERFORMANCE_INFORMATION>() as u32) }
        .as_bool().then_some(performance);
    let mut lists: SYSTEM_MEMORY_LIST_INFORMATION = unsafe { std::mem::zeroed() };
    let read_lists = unsafe { NtQuerySystemInformation(SystemMemoryListInformation, (&mut lists as *mut SYSTEM_MEMORY_LIST_INFORMATION).cast(), size_of::<SYSTEM_MEMORY_LIST_INFORMATION>() as u32, std::ptr::null_mut()) } >= 0;
    let page = performance.as_ref().map(|info| info.PageSize as u64);
    let mut details = categories(performance.as_ref(), read_lists.then_some(&lists), page);
    details.compressed = compressed();
    let (installed, inventory) = super::memory_inventory::read(memory.total_physical);
    details.installed = installed;
    memory.details = Some(details);
    memory.inventory = inventory;
    Some(memory)
}

fn compressed() -> Option<u64> {
    #[repr(C)]
    struct Compression {
        version: u32,
        pid: u32,
        working_set: u32,
        padding: u32,
        total_data_compressed: usize,
        total_compressed_size: usize,
        total_unique_data_compressed: usize,
    }
    #[repr(C)]
    struct Store {
        version: u32,
        class: u32,
        data: *mut std::ffi::c_void,
        length: u32,
    }
    let mut compression = Compression {
        version: 3, pid: 0, working_set: 0, padding: 0,
        total_data_compressed: 0, total_compressed_size: 0, total_unique_data_compressed: 0,
    };
    let mut store = Store {
        version: 1, class: 22,
        data: (&mut compression as *mut Compression).cast(),
        length: size_of::<Compression>() as u32,
    };
    let status = unsafe { NtQuerySystemInformation(109, (&mut store as *mut Store).cast(), size_of::<Store>() as u32, std::ptr::null_mut()) };
    if status < 0 || compression.pid == 0 {
        return None;
    }
    let process = crate::win::OwnedProcess::open(PROCESS_QUERY_LIMITED_INFORMATION, compression.pid).ok()?;
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    unsafe { GetProcessMemoryInfo(process.0, &mut counters, size_of::<PROCESS_MEMORY_COUNTERS>() as u32) }
        .as_bool().then_some(counters.WorkingSetSize as u64)
}

fn categories(performance: Option<&PERFORMANCE_INFORMATION>, lists: Option<&SYSTEM_MEMORY_LIST_INFORMATION>, page: Option<u64>) -> MemoryDetails {
    let bytes = |pages: usize| page.filter(|page| *page != 0)?.checked_mul(pages.try_into().ok()?);
    let mut result = MemoryDetails::default();
    if let Some(info) = performance {
        result.paged_pool = bytes(info.KernelPaged);
        result.non_paged_pool = bytes(info.KernelNonpaged);
    }
    if let Some(lists) = lists {
        result.standby = lists.PageCountByPriority.iter().try_fold(0usize, |sum, value| sum.checked_add(*value)).and_then(bytes);
        result.modified = bytes(lists.ModifiedPageCount);
        result.free = lists.ZeroPageCount.checked_add(lists.FreePageCount).and_then(bytes);
        result.cached = result.standby.zip(result.modified).and_then(|(standby, modified)| standby.checked_add(modified));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_memory_sources_keep_cached_inventory_separate_from_live_counters() {
        let first = read().expect("physical memory");
        let second = read().expect("physical memory");
        assert!(first.total_physical > 0);
        assert!(first.available_physical <= first.total_physical);
        assert!(std::sync::Arc::ptr_eq(first.inventory.as_ref().unwrap(), second.inventory.as_ref().unwrap()));
        println!("memory={}", serde_json::to_string(&second).unwrap());
    }

    #[test]
    fn lists_use_pages_and_keep_real_zero_distinct_from_failure() {
        let mut lists: SYSTEM_MEMORY_LIST_INFORMATION = unsafe { std::mem::zeroed() };
        lists.PageCountByPriority = [1; 8];
        lists.ModifiedPageCount = 3;
        lists.ZeroPageCount = 2;
        lists.FreePageCount = 4;
        let result = categories(None, Some(&lists), Some(4096));
        assert_eq!(result.standby, Some(8 * 4096));
        assert_eq!(result.modified, Some(3 * 4096));
        assert_eq!(result.cached, Some(11 * 4096));
        assert_eq!(result.free, Some(6 * 4096));
        assert_eq!(categories(None, None, Some(4096)).free, None);
        lists.FreePageCount = 0;
        lists.ZeroPageCount = 0;
        assert_eq!(categories(None, Some(&lists), Some(4096)).free, Some(0));
        lists.PageCountByPriority = [usize::MAX; 8];
        assert_eq!(categories(None, Some(&lists), Some(4096)).standby, None);
    }
}
