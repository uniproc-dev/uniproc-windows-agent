//! Manual end-to-end check against a running agent:
//!   cargo run --example rpc_client -- [service_name]
//!
//! Calls ping, getReport, process commands on a self-spawned child, and a
//! service restart (default: Spooler) with a concurrent ping to prove the
//! RPC thread is not blocked by Win32 calls.

use std::time::Instant;

use ogurpchik::auth::handshake::HandshakeMode;
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::windows_capnp::windows_agent;

struct ClientStub;
impl windows_agent::Server for ClientStub {}

fn main() {
    let service = std::env::args().nth(1).unwrap_or_else(|| "Spooler".into());
    compio::runtime::Runtime::new()
        .unwrap()
        .block_on(run(service))
        .unwrap();
}

async fn run(service: String) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::for_service("uniproc", "windows-agent")?;
    let session = connect_session::<windows_agent::Client, _>(
        &endpoint,
        &HandshakeMode::version_only(),
        ClientStub,
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    let client = session.remote().clone();

    client.ping_request().send().promise.await?;
    println!("ping: ok");

    let reply = client.get_report_request().send().promise.await?;
    let report = reply.get()?.get_report()?;
    let machine = report.get_machine()?;
    println!(
        "getReport: {} processes, cpu {:.1}%, mem used {} kb, net rx {} tx {}",
        report.get_processes()?.len(),
        machine.get_cpu_percent(),
        machine.get_used_physical_kb(),
        machine.get_net_rx_bytes(),
        machine.get_net_tx_bytes(),
    );

    // Process commands on our own child process.
    let mut child = std::process::Command::new("ping")
        .args(["-n", "60", "127.0.0.1"])
        .spawn()?;
    let pid = child.id();

    let mut req = client.suspend_request();
    req.get().set_pid(pid);
    let code = req.send().promise.await?.get()?.get_code();
    println!("suspend({pid}): code={code}");

    let mut req = client.resume_request();
    req.get().set_pid(pid);
    let code = req.send().promise.await?.get()?.get_code();
    println!("resume({pid}): code={code}");

    let mut req = client.kill_request();
    req.get().set_pid(pid);
    let code = req.send().promise.await?.get()?.get_code();
    println!("kill({pid}): code={code}");
    let _ = child.wait();

    // Unknown service: exercises the Win32 error mapping (expect 1060).
    let mut req = client.service_stop_request();
    req.get().set_name("DefinitelyNotAService12345");
    let code = req.send().promise.await?.get()?.get_code();
    println!("serviceStop(nonexistent): code={code} (expect 1060)");

    // Restart a real service while pinging: ping must answer immediately
    // even though restart blocks for seconds on a worker thread.
    let restart_client = client.clone();
    let restart_service = service.clone();
    let restart = compio::runtime::spawn(async move {
        let mut req = restart_client.service_restart_request();
        req.get().set_name(&restart_service);
        let reply = req.send().promise.await?;
        Ok::<u32, capnp::Error>(reply.get()?.get_code())
    });

    let ping_client = client.clone();
    let pings = compio::runtime::spawn(async move {
        let mut worst_ms = 0f64;
        for _ in 0..20 {
            let started = Instant::now();
            if ping_client.ping_request().send().promise.await.is_ok() {
                worst_ms = worst_ms.max(started.elapsed().as_secs_f64() * 1000.0);
            }
            compio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        worst_ms
    });

    let restart_code = restart.await.map_err(|_| "restart task panicked")??;
    let worst_ms = pings.await.map_err(|_| "pings task panicked")?;
    println!("serviceRestart({service}): code={restart_code}");
    println!("worst ping latency during restart: {worst_ms:.1} ms");

    // Two restarts of the same service in parallel must serialize through
    // the inflight guard: one runs, the other gets ERROR_BUSY (170).
    let spawn_restart = |client: windows_agent::Client, service: String| {
        compio::runtime::spawn(async move {
            let mut req = client.service_restart_request();
            req.get().set_name(&service);
            let reply = req.send().promise.await?;
            Ok::<u32, capnp::Error>(reply.get()?.get_code())
        })
    };
    let first = spawn_restart(client.clone(), service.clone());
    let second = spawn_restart(client.clone(), service.clone());
    let mut codes = [
        first.await.map_err(|_| "panicked")??,
        second.await.map_err(|_| "panicked")??,
    ];
    codes.sort();
    println!("parallel restarts: codes={codes:?} (expect [0, 170])");

    Ok(())
}
