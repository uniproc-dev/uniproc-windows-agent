//! Manual end-to-end check against the Linux agent running in WSL:
//!   cargo run --example linux_rpc_client
//!
//! Connects over Hyper-V vsock (host -> best VM, port 5000), calls ping and
//! getReport. The WSL guest can only *listen* on vsock, so the host is always
//! the connecting side.

use ogurpchik::auth::handshake::HandshakeMode;
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::linux_capnp::linux_agent;

const AGENT_VSOCK_PORT: u32 = 5000;

struct ClientStub;
impl linux_agent::Server for ClientStub {}

fn main() -> anyhow::Result<()> {
    compio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let endpoint = Endpoint::vsock_to_best_vm(AGENT_VSOCK_PORT)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let session = connect_session::<linux_agent::Client, _>(
        &endpoint,
        &HandshakeMode::version_only(),
        ClientStub,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let client = session.remote().clone();

    client.ping_request().send().promise.await?;
    println!("ping: ok");

    let reply = client.get_report_request().send().promise.await?;
    let report = reply.get()?.get_report()?;
    let machine = report.get_machine()?;
    let processes = report.get_processes()?;
    println!(
        "getReport: {} processes, {} environments, {} docker containers, mem used {} kb, busy {} ns",
        processes.len(),
        report.get_environments()?.len(),
        report.get_docker_containers()?.len(),
        machine.get_used_kb(),
        machine.get_busy_ns(),
    );

    for p in processes.iter().take(8) {
        println!(
            "    pid={:<6} name={:<20} cpu={:.1}% rss={} kb",
            p.get_global_pid(),
            p.get_name()?.to_str()?,
            p.get_cpu_percent(),
            p.get_rss_kb(),
        );
    }

    Ok(())
}
