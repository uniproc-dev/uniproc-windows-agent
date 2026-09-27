//! Manual end-to-end check of `Agent`, driven from a plain futures executor:
//!   cargo run --example agent -- remote      (against the running service)
//!   cargo run --example agent -- local       (in this process; run it elevated)

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{
    Command, MachineMetrics, MetricSpec, NO_DATA_U32, ProcessMetric, ProcessPriority, ServiceState,
    Snapshot,
};

fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "remote".into());
    futures::executor::block_on(run(&mode))
}

async fn snapshot(agent: &Agent) -> anyhow::Result<Snapshot> {
    for _ in 0..20 {
        if let Some(snapshot) = agent.snapshot().await?
            && snapshot.processes.value.len() > 10
        {
            return Ok(snapshot);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    anyhow::bail!("no usable snapshot")
}

async fn run(mode: &str) -> anyhow::Result<()> {
    let agent = match mode {
        "local" => Agent::local()?,
        _ => Agent::remote(Duration::from_secs(5)).await?,
    };
    agent.ping().await?;
    println!("{mode}: ping ok");

    let first = snapshot(&agent).await?;
    let states = &first.states.value;
    assert_eq!(states.passport_etag, first.processes.etag, "the states are joined with the list");
    assert_eq!(states.states.len(), first.processes.value.len(), "states cover the list");
    assert!(
        states
            .states
            .iter()
            .zip(first.processes.value.iter())
            .all(|(s, p)| (s.pid, s.sequence_number) == (p.pid, p.sequence_number))
    );
    let enriched = |p: &&uniproc_windows_agent::api::ProcessInfo| !p.user.is_empty();
    if let Some(p) = first
        .processes
        .value
        .iter()
        .filter(enriched)
        .find(|p| !p.package_full_name.is_empty())
    {
        println!(
            "{mode}: packaged {} app {:?} shown as {:?} by {:?}, isolation {:?}",
            p.package_full_name, p.package_relative_app_id, p.display_name, p.publisher, p.isolation
        );
        assert!(!p.package_relative_app_id.is_empty(), "a packaged process names its app");
        assert!(!p.publisher.is_empty(), "a package names its publisher");
    }
    let passports = first.processes.value.iter().filter(|p| !p.user.is_empty()).count();
    println!(
        "{mode}: {} processes ({passports} with a user), {} services",
        first.processes.value.len(),
        first.services.value.len(),
    );

    let spec = MetricSpec {
        interval: Duration::from_millis(500),
        processes: [
            ProcessMetric::WorkingSet,
            ProcessMetric::CpuUserTime,
            ProcessMetric::Handles,
            ProcessMetric::GdiObjects,
            ProcessMetric::UserObjects,
        ]
        .into_iter()
        .collect(),
        machine: MachineMetrics::all(),
    };
    let mut sampler = agent.subscribe(spec).await?;
    let a = sampler.next().await?;
    let b = sampler.next().await?;
    assert!(b.snapshot > a.snapshot && b.sampled_at > a.sampled_at, "each next is a newer sample");
    assert_eq!(b.pids.len(), b.columns.working_set.as_ref().map_or(0, |c| c.len()));
    assert!(b.columns.threads.is_none(), "only the asked columns come");
    let memory = b.machine.memory.expect("the machine's memory was asked for");
    assert!(memory.total_physical > memory.available_physical);
    println!(
        "{mode}: samples {} and {} {:.0} ms apart, {} rows, {} MB of {} MB available",
        a.snapshot,
        b.snapshot,
        (b.sampled_at - a.sampled_at) as f64 / 10_000.0,
        b.pids.len(),
        memory.available_physical >> 20,
        memory.total_physical >> 20,
    );
    let explorer = first
        .processes
        .value
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case("explorer.exe"))
        .expect("a desktop session");
    let row = b.pids.iter().position(|&pid| pid == explorer.pid).expect("explorer sampled");
    match (&b.columns.gdi_objects, &b.columns.user_objects) {
        (Some(gdi), Some(user)) if gdi[row] == NO_DATA_U32 => {
            assert_eq!(user[row], NO_DATA_U32);
            let own = b
                .pids
                .iter()
                .zip(gdi.iter())
                .filter(|&(_, &g)| g != NO_DATA_U32 && g > 0)
                .count();
            println!(
                "{mode}: explorer in session {} has no GUI object counts from here; {own} processes of the agent's session have some",
                explorer.session_id
            );
        }
        (Some(gdi), Some(user)) => {
            println!(
                "{mode}: explorer in session {} has {} GDI and {} USER objects",
                explorer.session_id, gdi[row], user[row]
            );
            assert!(gdi[row] > 0 && user[row] > 0, "the desktop's session shows its GUI objects");
        }
        _ => panic!("GDI and USER objects were asked for and come together"),
    }
    drop(sampler);

    let second = snapshot(&agent).await?;
    if second.processes.etag == first.processes.etag {
        assert!(Arc::ptr_eq(&first.processes.value, &second.processes.value));
        println!("{mode}: an unchanged list came back as the same Arc");
    } else {
        println!("{mode}: the list changed between snapshots");
    }
    if second.services.etag == first.services.etag {
        assert!(Arc::ptr_eq(&first.services.value, &second.services.value));
    }

    let mut child = std::process::Command::new("ping")
        .args(["-n", "30", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id();
    let priority = agent
        .run(Command::SetPriority {
            pid,
            priority: ProcessPriority::BelowNormal,
        })
        .await?;
    let killed = agent.run(Command::Kill { pid }).await?;
    child.wait()?;
    let again = agent.run(Command::Kill { pid }).await?;
    println!("{mode}: set_priority {priority:?}, kill {killed:?}, kill again {again:?}");
    assert_eq!((priority, killed), (Ok(()), Ok(())));
    assert!(again.is_err(), "a gone process cannot be killed");

    let mut watch = agent.watch_service("EventLog").await?;
    let status = watch.next().await.expect("EventLog is there");
    assert_eq!(status.state, ServiceState::Running);
    drop(watch);
    let mut gone = agent.watch_service("uniproc-no-such-service").await?;
    assert!(gone.next().await.is_none(), "a watch on no service ends");
    println!("{mode}: watch EventLog {:?} pid {}, a watch on no service ended", status.state, status.pid);
    Ok(())
}
