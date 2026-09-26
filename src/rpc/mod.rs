mod handler;
mod mapping;

use anyhow::Result;
use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::accept_session;
use uniproc_protocol::windows_capnp::windows_agent;
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE, WINDOWS_SCHEMA_ID};

use crate::embedded::Embedded;
use crate::profile::{ATTACHED_MEMORY_INTERVAL, IDLE_MEMORY_INTERVAL};
use crate::rpc::handler::AgentImpl;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

pub async fn run(agent: Arc<Embedded>) -> Result<()> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let listener = endpoint.listen().await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let attached = Rc::new(Cell::new(0usize));

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
        attached.set(attached.get() + 1);
        agent.set_memory_interval(ATTACHED_MEMORY_INTERVAL);

        let agent = agent.clone();
        let attached = attached.clone();
        compio::runtime::spawn(async move {
            if let Err(e) = session.wait().await {
                tracing::warn!("rpc session ended: {e:?}");
            }
            attached.set(attached.get() - 1);
            if attached.get() == 0 {
                agent.set_memory_interval(IDLE_MEMORY_INTERVAL);
            }
        })
        .detach();
    }
}
