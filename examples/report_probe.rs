//! Read-only probe against a running agent:
//!   cargo run --example report_probe
//!
//! Calls ping, then the four read methods twice, a second apart, passing the
//! previous round's tags, and prints what came back.

use std::time::{Duration, Instant};

use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::windows_capnp::windows_agent;
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE, WINDOWS_SCHEMA_ID};

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
        SchemaId(WINDOWS_SCHEMA_ID),
        ClientStub,
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    let client = session.remote().clone();

    let started = Instant::now();
    client.ping_request().send().promise.await?;
    println!("ping: ok in {:.1} ms", started.elapsed().as_secs_f64() * 1000.0);

    let (mut services_etag, mut processes_etag) = (0u64, 0u64);
    for round in 1..=2 {
        let reply = client.get_machine_request().send().promise.await?;
        let machine = reply.get()?.get_machine()?;
        println!(
            "round {round}: cpu={:.1}% mem_used={} kb mem_total={} kb cpu_mhz={}/{}",
            machine.get_cpu_percent(),
            machine.get_used_physical_kb(),
            machine.get_total_physical_kb(),
            machine.get_cpu_current_mhz(),
            machine.get_cpu_max_mhz(),
        );
        println!(
            "         disk r/w={}/{} bytes  net rx/tx={}/{} bytes",
            machine.get_disk_read_bytes(),
            machine.get_disk_write_bytes(),
            machine.get_net_rx_bytes(),
            machine.get_net_tx_bytes(),
        );

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

        let reply = client.get_process_metrics_request().send().promise.await?;
        let metrics = reply.get()?.get_metrics()?;
        println!(
            "         getProcessMetrics: processesEtag {:#x}, {} rows",
            reply.get()?.get_processes_etag(),
            metrics.len(),
        );
        for m in metrics.iter().take(5) {
            println!(
                "         pid={} cpu={:.1}% ws={} kb",
                m.get_pid(),
                m.get_cpu_percent(),
                m.get_working_set_kb(),
            );
        }

        if round == 1 {
            compio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    Ok(())
}
