//! Manual end-to-end check of watchProcessEvents against the running service:
//!   cargo run --example process_events
//!
//! Prints what the replay holds, then starts `cmd /d /c exit 7` and waits
//! for its start and exit to come through.

use std::time::Duration;

use uniproc_windows_agent::api::{ProcessEventBatch, ProcessEventKind};
use uniproc_windows_agent::remote::Remote;

fn main() -> anyhow::Result<()> {
    futures::executor::block_on(run())
}

fn show(batch: &ProcessEventBatch, pid: Option<u32>) {
    for event in batch.events.iter().filter(|e| pid.is_none_or(|pid| e.pid == pid)) {
        match &event.kind {
            ProcessEventKind::Started(s) => println!(
                "  {} started pid={} seq={} parent={}/{} session={} user={} elevated={:?}\n    image={}\n    command={}\n    cwd={} task={} services={:?}",
                event.time,
                event.pid,
                event.sequence_number,
                s.parent_pid,
                s.parent_sequence_number,
                s.session_id,
                s.user,
                s.elevated,
                s.image_path,
                s.command_line,
                s.working_directory,
                s.scheduled_task,
                s.parent_services,
            ),
            ProcessEventKind::Exited(x) => println!("  {} exited pid={} seq={} {x:?}", event.time, event.pid, event.sequence_number),
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let remote = Remote::connect(Duration::from_secs(5)).await?;
    println!("agent speaks windows {}", remote.agent_version());
    let mut events = remote.watch_process_events().await?;

    let first = events.next().await?;
    let (started, exited) = first.events.iter().fold((0, 0), |(s, x), e| match e.kind {
        ProcessEventKind::Started(_) => (s + 1, x),
        ProcessEventKind::Exited(_) => (s, x + 1),
    });
    println!(
        "replay: history_from={} events={} ({started} starts, {exited} exits) lost={}",
        first.history_from,
        first.events.len(),
        first.lost
    );
    let mut replayed = first.events.len();
    while let Some(Ok(batch)) = futures::FutureExt::now_or_never(events.next()) {
        replayed += batch.events.len();
        println!("  and a batch of {} more, lost={}", batch.events.len(), batch.lost);
    }
    println!("replayed {replayed} events in all");

    let child = std::process::Command::new("cmd").args(["/d", "/c", "exit 7"]).spawn()?;
    let pid = child.id();
    println!("started cmd as pid {pid}");
    let mut seen = 0;
    while seen < 2 {
        let batch = events.next().await?;
        let mine = batch.events.iter().filter(|e| e.pid == pid).count();
        if mine > 0 {
            show(&batch, Some(pid));
            seen += mine;
        }
    }
    Ok(())
}
