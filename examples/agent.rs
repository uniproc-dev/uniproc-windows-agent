//! Manual end-to-end check of `Agent`, driven from a plain futures executor:
//!   cargo run --example agent -- remote      (against the running service)
//!   cargo run --example agent -- local       (in this process; run it elevated)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use uniproc_windows_agent::agent::{Agent, Watch};
use uniproc_windows_agent::api::{
    Command, MachineMetric, MachineMetrics, MetricSpec, NO_DATA_U32, ProcessMetric, ProcessPriority, ServiceState,
    Snapshot, Update,
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

/// The next watch update, checked against the lists it comes with.
async fn next(watch: &mut Watch) -> anyhow::Result<Update> {
    let update = watch.next().await?;
    assert_eq!(update.sample.passport_etag, update.snapshot.processes.etag, "the sample is taken against its lists");
    assert_eq!(update.sample.pids.len(), update.snapshot.processes.value.len(), "a row per listed process");
    assert_eq!(update.snapshot.states.value.passport_etag, update.snapshot.processes.etag);
    Ok(update)
}

/// Two GPU samples a second apart: each process's busiest engine, as Task
/// Manager's GPU column shows it, and the adapters.
async fn gpu(agent: &Agent, mode: &str, snapshot: &Snapshot) -> anyhow::Result<()> {
    let mut sampler = agent
        .subscribe(MetricSpec {
            interval: Duration::from_secs(1),
            processes: [ProcessMetric::GpuDedicated, ProcessMetric::GpuShared, ProcessMetric::GpuEngines]
                .into_iter()
                .collect(),
            machine: MachineMetrics::only(MachineMetric::Gpu),
        })
        .await?;
    let before = sampler.next().await?;
    let after = sampler.next().await?;
    drop(sampler);
    let adapters = after.machine.gpus.clone().expect("the gpu group was asked for");
    let Some(adapter) = adapters.first() else {
        println!("{mode}: no hardware GPU");
        return Ok(());
    };
    let wall = (after.sampled_at - before.sampled_at) as f64;
    let ran = |sample: &uniproc_windows_agent::api::Sample| -> HashMap<(u64, u64, u32), u64> {
        sample
            .gpu_engines
            .as_ref()
            .expect("the engines were asked for")
            .iter()
            .map(|e| ((sample.sequence_numbers[e.row as usize], e.adapter_luid, e.engine), e.running_time))
            .collect()
    };
    let (was, is) = (ran(&before), ran(&after));
    let mut busiest: HashMap<u64, (f64, u32)> = HashMap::new();
    for (&(sequence, luid, engine), &running) in &is {
        let share = running.wrapping_sub(*was.get(&(sequence, luid, engine)).unwrap_or(&running)) as f64 / wall;
        let best = busiest.entry(sequence).or_insert((0.0, engine));
        if share > best.0 {
            *best = (share, engine);
        }
    }
    let mut top: Vec<(u64, (f64, u32))> = busiest.into_iter().collect();
    top.sort_by(|a, b| b.1.0.total_cmp(&a.1.0));
    let name = |sequence: u64| {
        snapshot
            .processes
            .value
            .iter()
            .find(|p| p.sequence_number == sequence)
            .map_or_else(|| "?".to_string(), |p| format!("{} ({})", p.name, p.pid))
    };
    for &(sequence, (share, engine)) in top.iter().take(5) {
        let kind = adapter.engines.iter().find(|e| e.ordinal == engine).map(|e| e.kind);
        println!("{mode}:   {:5.1}% on engine {engine} {kind:?}  {}", share * 100.0, name(sequence));
    }
    let dedicated = after.columns.gpu_dedicated.as_ref().expect("dedicated was asked for");
    let dwm = after
        .pids
        .iter()
        .zip(after.sequence_numbers.iter())
        .position(|(_, &sequence)| name(sequence).starts_with("dwm.exe"))
        .expect("a desktop");
    assert!(dedicated[dwm] > 0 && dedicated[dwm] != u64::MAX, "dwm holds video memory");
    let engines: Vec<String> = adapter
        .engines
        .iter()
        .map(|e| {
            let was = before.machine.gpus.as_ref().unwrap()[0].engines.iter().find(|w| w.ordinal == e.ordinal);
            let share = e.running_time.wrapping_sub(was.map_or(e.running_time, |w| w.running_time)) as f64 / wall;
            assert!(share <= 1.05, "engine {} ran {share} of the wall time", e.ordinal);
            format!("{}:{:?}{} {:.1}%", e.ordinal, e.kind, if e.name.is_empty() { "" } else { &e.name }, share * 100.0)
        })
        .collect();
    println!(
        "{mode}: {} dedicated {} of {} MB, shared {} of {} MB, {:.1} C, fan {} rpm, power {:.1}%, dwm holds {} MB; engines {}",
        adapter.name,
        adapter.dedicated_usage >> 20,
        adapter.dedicated_limit >> 20,
        adapter.shared_usage >> 20,
        adapter.shared_limit >> 20,
        adapter.temperature as f64 / 10.0,
        adapter.fan_rpm,
        adapter.power as f64 / 10.0,
        dedicated[dwm] >> 20,
        engines.join(", "),
    );
    Ok(())
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
    if let Some(p) = first
        .processes
        .value
        .iter()
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
            ProcessMetric::ContextSwitches,
            ProcessMetric::PeakThreads,
            ProcessMetric::PeakCommit,
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
    assert!(memory.committed > 0 && memory.committed <= memory.commit_limit);
    let cpu = b.machine.cpu.expect("the machine's cpu was asked for");
    let processors = b.machine.processors.clone().expect("the processors were asked for");
    assert_eq!(processors.iter().map(|p| p.user_time).sum::<u64>(), cpu.user_time, "one read for both");
    let switches = b.columns.context_switches.as_ref().expect("context switches were asked for");
    assert!(switches.iter().filter(|&&s| s > 0).count() > b.pids.len() / 2);
    println!(
        "{mode}: samples {} and {} {:.0} ms apart, {} rows, {} MB of {} MB available, {} of {} MB committed, {} processors",
        a.snapshot,
        b.snapshot,
        (b.sampled_at - a.sampled_at) as f64 / 10_000.0,
        b.pids.len(),
        memory.available_physical >> 20,
        memory.total_physical >> 20,
        memory.committed >> 20,
        memory.commit_limit >> 20,
        processors.len(),
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

    gpu(&agent, mode, &first).await?;

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

    let mut watch = agent
        .watch(MetricSpec {
            interval: Duration::from_millis(500),
            processes: [ProcessMetric::WorkingSet].into_iter().collect(),
            machine: MachineMetrics::empty(),
        })
        .await?;
    let update = next(&mut watch).await?;
    assert!(update.changes.full, "the first update carries everything");
    let mut child = std::process::Command::new("ping")
        .args(["-n", "30", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id();
    let mut updates = 1;
    loop {
        let update = next(&mut watch).await?;
        updates += 1;
        if update.changes.passports.iter().any(|&(p, _)| p == pid) {
            assert!(update.snapshot.processes.value.iter().any(|p| p.pid == pid));
            break;
        }
        assert!(updates < 40, "the child never showed up in a watch update");
    }
    child.kill()?;
    child.wait()?;
    loop {
        let update = next(&mut watch).await?;
        updates += 1;
        if update.changes.left.iter().any(|&(p, _)| p == pid) {
            assert!(!update.snapshot.processes.value.iter().any(|p| p.pid == pid));
            break;
        }
        assert!(updates < 80, "the child never left in a watch update");
    }
    drop(watch);
    println!("{mode}: watch saw a child join and leave in {updates} updates");

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
