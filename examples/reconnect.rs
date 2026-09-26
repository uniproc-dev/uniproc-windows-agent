//! Manual check against a running agent that one client process can connect
//! again after dropping a session, and hold two sessions at once:
//!   cargo run --example reconnect

use std::time::Duration;

use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::{RpcSession, connect_session};
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

async fn connect() -> Result<RpcSession<windows_agent::Client>, Box<dyn std::error::Error>> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE)?;
    let session = compio::time::timeout(
        Duration::from_secs(10),
        connect_session::<windows_agent::Client, _>(
            &endpoint,
            &HandshakeMode::version_only(),
            SchemaId(WINDOWS_SCHEMA_ID),
            ClientStub,
        ),
    )
    .await
    .map_err(|_| "connect timed out")?
    .map_err(|e| format!("{e:?}"))?;
    Ok(session)
}

async fn ping(session: &RpcSession<windows_agent::Client>, nonce: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = session.remote().ping_request();
    request.get().set_nonce(nonce);
    let reply = request.send().promise.await?;
    assert_eq!(reply.get()?.get_nonce(), nonce);
    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    for round in 1..=3u64 {
        let session = connect().await?;
        ping(&session, round).await?;
        drop(session);
        println!("sequential session {round}: ok");
    }

    let first = connect().await?;
    let second = connect().await?;
    ping(&first, 10).await?;
    ping(&second, 20).await?;
    println!("two sessions at once: ok");
    Ok(())
}
