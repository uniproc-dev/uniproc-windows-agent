//! Manual end-to-end check against the Linux agent running in WSL:
//!   cargo run --example linux_rpc_client
//!
//! Connects over Hyper-V vsock (host -> best VM, port 5000), calls ping,
//! getEnvironments and getProcesses. The WSL guest can only *listen* on vsock, so the host is always
//! the connecting side.

use ogurpchik::auth::handshake::{HandshakeMode, Protocol};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::linux_capnp::linux_agent;
use uniproc_protocol::{LINUX_PROTOCOL, WSL_AGENT_VSOCK_PORT};

struct ClientStub;
impl linux_agent::Server for ClientStub {}

fn main() -> anyhow::Result<()> {
    compio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let endpoint = Endpoint::vsock_to_wsl(WSL_AGENT_VSOCK_PORT)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let session = connect_session::<linux_agent::Client, _>(
        &endpoint,
        &HandshakeMode::version_only(),
        Protocol::new(
            LINUX_PROTOCOL.id,
            LINUX_PROTOCOL.major,
            LINUX_PROTOCOL.minor,
            LINUX_PROTOCOL.patch,
        ),
        ClientStub,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let client = session.remote().clone();

    client.ping_request().send().promise.await?;
    println!("ping: ok");

    let reply = client.get_environments_request().send().promise.await?;
    let environments = reply.get()?;
    println!(
        "getEnvironments: {} environments, {} docker containers",
        environments.get_environments()?.len(),
        environments.get_docker_containers()?.len(),
    );

    let reply = client.get_processes_request().send().promise.await?;
    let processes = reply.get()?.get_processes()?;
    println!("getProcesses: {} processes", processes.len());
    for p in processes.iter().take(8) {
        println!(
            "    pid={:<6} name={:<20} user={}",
            p.get_pid(),
            p.get_name()?.to_str()?,
            p.get_user()?.to_str()?,
        );
    }

    Ok(())
}
