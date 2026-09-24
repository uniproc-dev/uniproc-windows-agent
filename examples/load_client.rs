//! Load generator against a running agent, for profiling its request path:
//!   cargo run --release --example load_client -- [processes|metrics|refresh|ping] [inflight] [seconds]
//!
//! Opens one session (the agent serves one at a time) and keeps `inflight`
//! requests outstanding on it until the deadline, then prints throughput and
//! latency percentiles. Read-only: it never calls a method that changes the
//! machine.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::windows_capnp::windows_agent;
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE, WINDOWS_SCHEMA_ID};

struct ClientStub;
impl windows_agent::Server for ClientStub {}

#[derive(Clone, Copy)]
enum Method {
    Processes,
    Metrics,
    Refresh,
    Ping,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Processes => "getProcesses",
            Method::Metrics => "getProcessMetrics",
            Method::Refresh => "refresh",
            Method::Ping => "ping",
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let method = match args.next().as_deref() {
        None | Some("processes") => Method::Processes,
        Some("metrics") => Method::Metrics,
        Some("refresh") => Method::Refresh,
        Some("ping") => Method::Ping,
        Some(other) => panic!("unknown method {other:?}, expected processes, metrics, refresh or ping"),
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
}

async fn call(client: &windows_agent::Client, method: Method, tags: &mut Tags) -> Result<u64, capnp::Error> {
    match method {
        Method::Ping => {
            client.ping_request().send().promise.await?;
            Ok(0)
        }
        Method::Processes => {
            let reply = client.get_processes_request().send().promise.await?;
            Ok(reply.get()?.total_size()?.word_count * 8)
        }
        Method::Metrics => {
            let reply = client.get_process_metrics_request().send().promise.await?;
            Ok(reply.get()?.total_size()?.word_count * 8)
        }
        Method::Refresh => {
            let machine = client.get_machine_request().send().promise.await?;
            let mut bytes = machine.get()?.total_size()?.word_count * 8;

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

            let metrics = client.get_process_metrics_request().send().promise.await?;
            bytes += metrics.get()?.total_size()?.word_count * 8;
            Ok(bytes)
        }
    }
}

async fn run(method: Method, inflight: usize, length: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE)?;
    let session = connect_session::<windows_agent::Client, _>(
        &endpoint,
        &HandshakeMode::version_only(),
        SchemaId(WINDOWS_SCHEMA_ID),
        ClientStub,
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    let client = session.remote().clone();

    call(&client, method, &mut Tags::default()).await?;

    let latencies = Rc::new(RefCell::new(Vec::<u32>::with_capacity(1 << 20)));
    let errors = Rc::new(RefCell::new(0u64));
    let bytes = Rc::new(RefCell::new(0u64));
    let started = Instant::now();
    let deadline = started + length;

    let workers: Vec<_> = (0..inflight)
        .map(|_| {
            let client = client.clone();
            let latencies = latencies.clone();
            let errors = errors.clone();
            let bytes = bytes.clone();
            compio::runtime::spawn(async move {
                let mut tags = Tags::default();
                while Instant::now() < deadline {
                    let sent = Instant::now();
                    match call(&client, method, &mut tags).await {
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
