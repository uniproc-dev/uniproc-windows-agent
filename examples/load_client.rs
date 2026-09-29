//! Load generator against a running agent, for profiling its request path:
//!   cargo run --release --example load_client -- [processes|states|sample|refresh|ping] [inflight] [seconds]
//!   cargo run --release --example load_client -- split [machine ms] [seconds] [cpu,memory,disk,network,processors,gpu,adapters]
//!
//! Opens one session (the agent serves one at a time) and keeps `inflight`
//! requests outstanding on it until the deadline, then prints throughput and
//! latency percentiles. `split` subscribes twice, as uniproc does: the named
//! machine groups, all of them by default, every `machine ms`, every process
//! counter every 1.5 s, and counts what each subscription receives.
//! Read-only: it never calls a method that changes the machine.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use ogurpchik::auth::handshake::HandshakeMode;
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::windows_capnp::{sampler, windows_agent};
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE};
use uniproc_windows_agent::api::{MachineMetric, MachineMetrics, MetricSpec, ProcessMetrics};
use uniproc_windows_agent::wire::{PROTOCOL, encode};

struct ClientStub;
impl windows_agent::Server for ClientStub {}

#[derive(Clone, Copy)]
enum Method {
    Processes,
    States,
    Sample,
    Refresh,
    Ping,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Processes => "getProcesses",
            Method::States => "getProcessStates",
            Method::Sample => "sample",
            Method::Refresh => "refresh",
            Method::Ping => "ping",
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("split") {
        let machine_ms: u64 = args.next().map_or(100, |s| s.parse().expect("machine ms"));
        let seconds: u64 = args.next().map_or(15, |s| s.parse().expect("seconds"));
        let groups = args.next().map_or_else(MachineMetrics::all, |names| {
            names
                .split(',')
                .map(|name| match name {
                    "cpu" => MachineMetric::Cpu,
                    "memory" => MachineMetric::Memory,
                    "disk" => MachineMetric::Disk,
                    "network" => MachineMetric::Network,
                    "processors" => MachineMetric::Processors,
                    "gpu" => MachineMetric::Gpu,
                    "adapters" => MachineMetric::NetworkAdapters,
                    other => panic!("unknown machine group {other:?}"),
                })
                .collect()
        });
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(split(Duration::from_millis(machine_ms), groups, Duration::from_secs(seconds)))
            .unwrap();
        return;
    }
    let method = match first.as_deref() {
        None | Some("processes") => Method::Processes,
        Some("states") => Method::States,
        Some("sample") => Method::Sample,
        Some("refresh") => Method::Refresh,
        Some("ping") => Method::Ping,
        Some(other) => panic!("unknown method {other:?}, expected processes, states, sample, refresh or ping"),
    };
    let inflight: usize = args.next().map_or(16, |s| s.parse().expect("inflight"));
    let seconds: u64 = args.next().map_or(15, |s| s.parse().expect("seconds"));

    compio::runtime::Runtime::new()
        .unwrap()
        .block_on(run(method, inflight, Duration::from_secs(seconds)))
        .unwrap();
}

#[derive(Default, Clone, Copy)]
struct Tags {
    services: u64,
    processes: u64,
    states: u64,
}

async fn call(
    client: &windows_agent::Client,
    sampler: &sampler::Client,
    method: Method,
    tags: &mut Tags,
) -> Result<u64, capnp::Error> {
    match method {
        Method::Ping => {
            client.ping_request().send().promise.await?;
            Ok(0)
        }
        Method::Processes => {
            let reply = client.get_processes_request().send().promise.await?;
            Ok(reply.get()?.total_size()?.word_count * 8)
        }
        Method::States => {
            let reply = client.get_process_states_request().send().promise.await?;
            Ok(reply.get()?.total_size()?.word_count * 8)
        }
        Method::Sample => {
            let reply = sampler.sample_request().send().promise.await?;
            Ok(reply.get()?.total_size()?.word_count * 8)
        }
        Method::Refresh => {
            let sample = sampler.sample_request().send().promise.await?;
            let mut bytes = sample.get()?.total_size()?.word_count * 8;

            let mut req = client.get_services_request();
            req.get().init_meta().set_if_none_match(tags.services);
            let services = req.send().promise.await?;
            tags.services = services.get()?.get_meta()?.get_etag();
            bytes += services.get()?.total_size()?.word_count * 8;

            let mut req = client.get_processes_request();
            req.get().init_meta().set_if_none_match(tags.processes);
            let processes = req.send().promise.await?;
            tags.processes = processes.get()?.get_meta()?.get_etag();
            bytes += processes.get()?.total_size()?.word_count * 8;

            let mut req = client.get_process_states_request();
            req.get().init_meta().set_if_none_match(tags.states);
            let states = req.send().promise.await?;
            tags.states = states.get()?.get_meta()?.get_etag();
            bytes += states.get()?.total_size()?.word_count * 8;
            Ok(bytes)
        }
    }
}

async fn subscribe(client: &windows_agent::Client, spec: &MetricSpec) -> Result<sampler::Client, capnp::Error> {
    let mut req = client.subscribe_request();
    encode::metric_spec(spec, req.get().init_spec());
    req.send().promise.await?.get()?.get_sampler()
}

async fn split(
    machine_every: Duration,
    groups: MachineMetrics,
    length: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE)?;
    let session = connect_session::<windows_agent::Client, _>(
        &endpoint,
        &HandshakeMode::version_only(),
        PROTOCOL,
        ClientStub,
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    let client = session.remote().clone();
    let specs = [
        (
            "machine",
            MetricSpec {
                interval: machine_every,
                processes: ProcessMetrics::empty(),
                machine: groups,
            },
        ),
        (
            "processes",
            MetricSpec {
                interval: Duration::from_millis(1500),
                processes: ProcessMetrics::all(),
                machine: MachineMetrics::empty(),
            },
        ),
    ];
    let deadline = Instant::now() + length;
    let mut polls = Vec::new();
    for (name, spec) in specs {
        let sampler = subscribe(&client, &spec).await?;
        polls.push(compio::runtime::spawn(async move {
            let (mut last, mut samples, mut rows, mut bytes) = (0u64, 0u64, 0u64, 0u64);
            let mut totals = Vec::new();
            while Instant::now() < deadline {
                let mut req = sampler.sample_request();
                req.get().init_meta().set_if_none_match(last);
                let Ok(reply) = req.send().promise.await else { break };
                let Ok(reply) = reply.get() else { break };
                last = reply.get_meta().map_or(0, |m| m.get_etag());
                rows += reply.get_processes().and_then(|p| p.get_pids()).map_or(0, |p| p.len() as u64);
                bytes += reply.total_size().map_or(0, |s| s.word_count * 8);
                samples += 1;
                if let Ok(machine) = reply.get_machine() {
                    let disk = machine.get_disk().map_or(0, |d| d.get_read_bytes() + d.get_write_bytes());
                    let network = machine.get_network().map_or(0, |n| n.get_rx_bytes() + n.get_tx_bytes());
                    totals.push((disk, network));
                }
            }
            (name, samples, rows, bytes, totals)
        }));
    }
    for poll in polls {
        if let Ok((name, samples, rows, bytes, totals)) = poll.await {
            let seconds = length.as_secs_f64();
            println!(
                "{name}: {samples} samples, {:.1}/s, {:.0} rows and {:.1} KiB per sample",
                samples as f64 / seconds,
                rows as f64 / samples.max(1) as f64,
                bytes as f64 / samples.max(1) as f64 / 1024.0,
            );
            let moved = totals.windows(2).filter(|w| w[1] != w[0]).count();
            if let (Some(first), Some(last)) = (totals.first(), totals.last()) {
                println!(
                    "    disk+network bytes: first {first:?}, last {last:?}, moved between {moved} of {} samples",
                    totals.len().saturating_sub(1)
                );
            }
        }
    }
    Ok(())
}

async fn run(method: Method, inflight: usize, length: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE)?;
    let session = connect_session::<windows_agent::Client, _>(
        &endpoint,
        &HandshakeMode::version_only(),
        PROTOCOL,
        ClientStub,
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    let client = session.remote().clone();
    let every = MetricSpec {
        interval: Duration::from_secs(1),
        processes: ProcessMetrics::all(),
        machine: MachineMetrics::all(),
    };
    let sampler = subscribe(&client, &every).await?;

    call(&client, &sampler, method, &mut Tags::default()).await?;

    let latencies = Rc::new(RefCell::new(Vec::<u32>::with_capacity(1 << 20)));
    let errors = Rc::new(RefCell::new(0u64));
    let bytes = Rc::new(RefCell::new(0u64));
    let started = Instant::now();
    let deadline = started + length;

    let workers: Vec<_> = (0..inflight)
        .map(|_| {
            let client = client.clone();
            let sampler = sampler.clone();
            let latencies = latencies.clone();
            let errors = errors.clone();
            let bytes = bytes.clone();
            compio::runtime::spawn(async move {
                let mut tags = Tags::default();
                while Instant::now() < deadline {
                    let sent = Instant::now();
                    match call(&client, &sampler, method, &mut tags).await {
                        Ok(n) => {
                            *bytes.borrow_mut() += n;
                            latencies
                                .borrow_mut()
                                .push(sent.elapsed().as_micros().min(u32::MAX as u128) as u32)
                        }
                        Err(_) => *errors.borrow_mut() += 1,
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        let _ = worker.await;
    }
    let elapsed = started.elapsed().as_secs_f64();

    let mut latencies = latencies.take();
    latencies.sort_unstable();
    let pick = |q: f64| {
        latencies
            .get(((latencies.len() as f64 - 1.0) * q).round() as usize)
            .copied()
            .unwrap_or(0) as f64
            / 1000.0
    };
    let done = latencies.len();
    let rps = done as f64 / elapsed;

    println!(
        "{} x{inflight} for {elapsed:.1}s: {done} ok, {} failed, {rps:.0} req/s",
        method.name(),
        errors.take(),
    );
    println!(
        "latency ms: p50 {:.3}  p90 {:.3}  p99 {:.3}  p99.9 {:.3}  max {:.3}",
        pick(0.5),
        pick(0.9),
        pick(0.99),
        pick(0.999),
        pick(1.0),
    );
    let bytes = bytes.take();
    if bytes > 0 && done > 0 {
        println!(
            "reply {:.1} KiB on average, {:.1} MiB/s",
            bytes as f64 / done as f64 / 1024.0,
            bytes as f64 / elapsed / (1024.0 * 1024.0),
        );
    }
    Ok(())
}
