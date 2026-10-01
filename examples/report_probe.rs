//! Read-only probe against a running agent:
//!   cargo run --example report_probe
//!
//! Calls ping, subscribes, then samples and calls the three read methods
//! twice, passing the previous round's tags, and prints what came back.

use std::time::{Duration, Instant};

use ogurpchik::auth::handshake::HandshakeMode;
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::windows_capnp::windows_agent;
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE};
use uniproc_windows_agent::api::{MachineMetrics, MetricSpec, ProcessMetric};
use uniproc_windows_agent::wire::{PROTOCOL, decode, encode};

struct ClientStub;
impl windows_agent::Server for ClientStub {}

fn main() {
    compio::runtime::Runtime::new()
        .unwrap()
        .block_on(run())
        .unwrap();
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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

    let started = Instant::now();
    client.ping_request().send().promise.await?;
    println!("ping: ok in {:.1} ms", started.elapsed().as_secs_f64() * 1000.0);

    let spec = MetricSpec {
        interval: Duration::from_secs(1),
        processes: [ProcessMetric::WorkingSet, ProcessMetric::CpuUserTime, ProcessMetric::CpuKernelTime]
            .into_iter()
            .collect(),
        machine: MachineMetrics::all(),
    };
    let mut req = client.subscribe_request();
    encode::metric_spec(&spec, req.get().init_spec());
    let sampler = req.send().promise.await?.get()?.get_sampler()?;

    let (mut services_etag, mut processes_etag, mut states_etag, mut snapshot) = (0u64, 0u64, 0u64, 0u64);
    for round in 1..=2 {
        let started = Instant::now();
        let mut req = sampler.sample_request();
        req.get().init_meta().set_if_none_match(snapshot);
        let reply = req.send().promise.await?;
        let sample = decode::sample(reply.get()?.get_processes()?, reply.get()?.get_machine()?, spec)?;
        snapshot = sample.snapshot;
        println!(
            "round {round}: sample {} after {:.0} ms, sampledAt {}, passport {:#x}, {} rows",
            sample.snapshot,
            started.elapsed().as_secs_f64() * 1000.0,
            sample.sampled_at,
            sample.passport_etag,
            sample.pids.len(),
        );
        println!("         machine {:?}", sample.machine);
        if let Some(ws) = &sample.columns.working_set {
            for (pid, ws) in sample.pids.iter().zip(ws.iter()).take(5) {
                println!("         pid={pid} ws={} kb", ws >> 10);
            }
        }

        let mut req = client.get_services_request();
        req.get().init_meta().set_if_none_match(services_etag);
        let reply = req.send().promise.await?;
        let meta = reply.get()?.get_meta()?;
        println!(
            "         getServices(ifNoneMatch {services_etag:#x}): {:?} etag {:#x}, {} services",
            meta.get_status()?,
            meta.get_etag(),
            reply.get()?.get_services()?.len(),
        );
        services_etag = meta.get_etag();

        let mut req = client.get_processes_request();
        req.get().init_meta().set_if_none_match(processes_etag);
        let reply = req.send().promise.await?;
        let meta = reply.get()?.get_meta()?;
        let processes = reply.get()?.get_processes()?;
        println!(
            "         getProcesses(ifNoneMatch {processes_etag:#x}): {:?} etag {:#x}, {} processes",
            meta.get_status()?,
            meta.get_etag(),
            processes.len(),
        );
        processes_etag = meta.get_etag();
        for p in processes.iter().take(5) {
            println!(
                "         pid={} {} console_host={} cmdline_args={}",
                p.get_pid(),
                p.get_name()?.to_str()?,
                p.get_console_host_pid(),
                p.get_cmdline()?.len(),
            );
        }

        let mut req = client.get_process_states_request();
        req.get().init_meta().set_if_none_match(states_etag);
        let reply = req.send().promise.await?;
        let meta = reply.get()?.get_meta()?;
        let states = decode::process_states(reply.get()?.get_states()?);
        println!(
            "         getProcessStates(ifNoneMatch {states_etag:#x}): {:?} etag {:#x}, passport {:#x}, {} states",
            meta.get_status()?,
            meta.get_etag(),
            reply.get()?.get_passport_etag(),
            states.len(),
        );
        states_etag = meta.get_etag();
        for s in states.iter().filter(|s| s.efficiency_mode == Some(true)).take(5) {
            println!("         efficiency mode: {s:?}");
        }
        let unknown = states.iter().filter(|s| s.vm_host.is_none()).count();
        println!("         vm hosts ({unknown} unknown):");
        for s in states.iter().filter(|s| s.vm_host == Some(true)) {
            println!("         vm host: pid={} sequence_number={}", s.pid, s.sequence_number);
        }
    }

    Ok(())
}
