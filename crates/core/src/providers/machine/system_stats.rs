use crate::bindings::{GetPerformanceInfo, GetTickCount64, PERFORMANCE_INFORMATION};
use crate::sample::MachineSystemStats;

pub fn read() -> Option<MachineSystemStats> {
    let mut info = PERFORMANCE_INFORMATION {
        cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
        ..Default::default()
    };
    let read =
        unsafe { GetPerformanceInfo(&mut info, size_of::<PERFORMANCE_INFORMATION>() as u32) }
            .as_bool();
    snapshot(read.then_some(info), unsafe { GetTickCount64() })
}

fn snapshot(info: Option<PERFORMANCE_INFORMATION>, uptime_ms: u64) -> Option<MachineSystemStats> {
    let info = info?;
    Some(MachineSystemStats {
        process_count: info.ProcessCount,
        thread_count: info.ThreadCount,
        handle_count: info.HandleCount,
        uptime_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_machine_system_stats_are_read_without_a_service_or_process_scan() {
        let sample = read().expect("system performance information");
        assert!(sample.process_count > 0);
        assert!(sample.thread_count > 0);
        assert!(sample.handle_count > 0);
        assert!(sample.uptime_ms > 0);
        println!("system_stats={}", serde_json::to_string(&sample).unwrap());
    }

    #[test]
    fn all_counts_come_from_one_snapshot_and_uptime_keeps_its_width() {
        let info = PERFORMANCE_INFORMATION {
            ProcessCount: 501,
            ThreadCount: 12003,
            HandleCount: 100_001,
            ..Default::default()
        };
        let sample = snapshot(Some(info), u64::from(u32::MAX) + 123).unwrap();
        assert_eq!(
            (
                sample.process_count,
                sample.thread_count,
                sample.handle_count
            ),
            (501, 12003, 100_001)
        );
        assert_eq!(sample.uptime_ms, u64::from(u32::MAX) + 123);
        assert_eq!(snapshot(None, 123), None);
    }
}
