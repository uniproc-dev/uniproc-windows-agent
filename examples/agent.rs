//! Manual end-to-end check of `Agent`, driven from a plain futures executor:
//!   cargo run --example agent -- remote      (against the running service)
//!   cargo run --example agent -- embedded    (in this process; run it elevated)

use std::sync::Arc;
use std::time::Duration;

use uniproc_windows_agent::agent::Agent;
use uniproc_windows_agent::api::{Command, ProcessPriority, Snapshot};

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
        "embedded" => Agent::embedded()?,
        _ => Agent::remote(Duration::from_secs(5)).await?,
    };
    agent.ping().await?;
    println!("{mode}: ping ok");

    let first = snapshot(&agent).await?;
    assert_eq!(first.metrics.len(), first.processes.value.len(), "metrics cover the list");
    assert!(first.metrics.iter().zip(first.processes.value.iter()).all(|(m, p)| m.pid == p.pid));
    println!(
        "{mode}: {} processes, {} services, cpu {:.1}%, used {} kb",
        first.processes.value.len(),
        first.services.value.len(),
        first.machine.cpu_percent,
        first.machine.used_physical_kb,
    );

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

    agent
        .set_intervals(Some(Duration::from_millis(1000)), None)
        .await?;
    println!("{mode}: set_intervals ok");

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
    Ok(())
}
