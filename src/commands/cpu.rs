use std::time::{Duration, Instant};

use anyhow::Result;

use crate::providers::Supervisor;
use crate::supervisor::SupervisorConfig;

const DEBUG_SESSION_NAMESPACE: &str = "Uniproc-Debug-";

pub fn run(iterations: u32, top: usize) -> Result<()> {
    let mut supervisor = Supervisor::default();
    supervisor.set_config(SupervisorConfig {
        session_namespace: Some(DEBUG_SESSION_NAMESPACE.to_string()),
        ..Default::default()
    });
    supervisor.start()?;

    let state = supervisor.state();
    let tick = supervisor.tick_interval();

    let mut printed = 0u32;
    let mut next_print = Instant::now() + Duration::from_secs(1);

    while printed < iterations {
        supervisor.tick();

        if Instant::now() >= next_print {
            next_print += Duration::from_secs(1);
            printed += 1;

            let guard = state.lock();

            let (busy, interrupt, dpc) = match guard.machine() {
                Some(m) => (m.cpu_percent, m.cpu_interrupt_percent, m.cpu_dpc_percent),
                None => (0.0, 0.0, 0.0),
            };
            let attributable = (busy - interrupt - dpc).max(0.0);

            let mut rows: Vec<(f64, u32, String)> = guard
                .entries()
                .filter(|e| e.cpu.total_percent > 0.0)
                .map(|e| {
                    let name = if e.exited {
                        format!("{} (exited)", e.image_name)
                    } else {
                        e.image_name.clone()
                    };
                    (e.cpu.total_percent, e.pid, name)
                })
                .collect();
            rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

            let charged: f64 = rows.iter().map(|r| r.0).sum();
            let (attributed_samples, unattributed_samples, idle_samples) = guard.sample_counts();

            println!();
            println!(
                "busy {busy:>6.2}%   interrupt {interrupt:>5.2}%   dpc {dpc:>5.2}%   attributable {attributable:>6.2}%"
            );
            println!(
                "charged to processes {charged:>6.2}%   over {} rows",
                rows.len()
            );
            let counted = (attributed_samples + unattributed_samples) as f64;
            let share = |part: u64| {
                if counted > 0.0 {
                    (part as f64 / counted) * 100.0
                } else {
                    0.0
                }
            };
            println!(
                "samples: attributed {attributed_samples} ({:.1}%)   unattributed {unattributed_samples} ({:.1}%)   idle {idle_samples}",
                share(attributed_samples),
                share(unattributed_samples)
            );
            println!(
                "unattributed time {:>6.2}%   of the machine",
                attributable as f64 * share(unattributed_samples) / 100.0
            );
            let dropped = supervisor.dropped();
            println!(
                "sink dropped {dropped}   processes {}   machine {}",
                guard.len(),
                guard.machine().is_some()
            );
            println!("{:-<52}", "");

            for (percent, pid, name) in rows.iter().take(top) {
                println!("{percent:>6.2}%  {pid:>7}  {name}");
            }

            drop(guard);
        }

        std::thread::sleep(tick);
    }

    supervisor.stop();
    Ok(())
}
