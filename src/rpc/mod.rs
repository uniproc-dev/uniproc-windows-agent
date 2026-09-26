mod handler;
mod mapping;

use anyhow::Result;
use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::accept_session;
use uniproc_protocol::windows_capnp::windows_agent;
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE, WINDOWS_SCHEMA_ID};

use crate::embedded::Embedded;
use crate::rpc::handler::AgentImpl;
use std::sync::Arc;
use std::time::Duration;

use crate::settings::{ATTACHED_MEMORY_INTERVAL_MS, IDLE_MEMORY_INTERVAL_MS};

pub async fn run(agent: Arc<Embedded>) -> Result<()> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let listener = endpoint.listen().await.map_err(|e| anyhow::anyhow!("{e:?}"))?;

    loop {
        let session = match accept_session::<windows_agent::Client, _>(
            &listener,
            &HandshakeMode::version_only(),
            SchemaId(WINDOWS_SCHEMA_ID),
            AgentImpl::new(agent.clone()),
        )
        .await
        {
            Ok(session) => session,
            Err(e) => {
                tracing::error!("accept_session failed: {e:?}");
                continue;
            }
        };
        agent.set_memory_interval(Duration::from_millis(ATTACHED_MEMORY_INTERVAL_MS));

        // One connection at a time; a disconnect must not kill the loop.
        if let Err(e) = session.wait().await {
            tracing::warn!("rpc session ended: {e:?}");
        }

        agent.set_memory_interval(Duration::from_millis(IDLE_MEMORY_INTERVAL_MS));
    }
}
