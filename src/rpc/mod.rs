mod handler;
mod mapping;
mod vars;

use anyhow::Result;
use ogurpchik::auth::handshake::HandshakeMode;
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::accept_session;
use uniproc_protocol::windows_capnp::windows_agent;

use crate::commands::Commands;
use crate::monitor::SharedSupervisor;
use crate::rpc::handler::AgentImpl;
use crate::rpc::vars::{AGENT_SERVICE_NAME, APP_NAME};

pub async fn run(supervisor: SharedSupervisor) -> Result<()> {
    let endpoint = Endpoint::for_service(APP_NAME, AGENT_SERVICE_NAME)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let listener = endpoint.listen().await.map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let (state, settings) = {
        let supervisor = supervisor.lock();
        (supervisor.state(), supervisor.settings())
    };
    let commands = Commands::new();

    loop {
        let session = match accept_session::<windows_agent::Client, _>(
            &listener,
            &HandshakeMode::version_only(),
            AgentImpl::new(
                supervisor.clone(),
                state.clone(),
                settings.clone(),
                commands.clone(),
            ),
        )
        .await
        {
            Ok(session) => session,
            Err(e) => {
                tracing::error!("accept_session failed: {e:?}");
                continue;
            }
        };
        // One connection at a time; a disconnect must not kill the loop.
        if let Err(e) = session.wait().await {
            tracing::warn!("rpc session ended: {e:?}");
        }
    }
}
