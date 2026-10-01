mod handler;

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
use ogurpchik::auth::handshake::HandshakeMode;
use ogurpchik::endpoint::Endpoint;
pub use ogurpchik::net::Listener;
use ogurpchik::rpc::SessionAcceptor;
use uniproc_protocol::windows_capnp::windows_agent;
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE};
use uniproc_windows_agent::local::Local;
use uniproc_windows_agent::wire::PROTOCOL;

use crate::handler::AgentImpl;

/// The service's pipe, bound; fails when another process holds its name.
pub async fn listen() -> Result<Listener> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    endpoint
        .listen()
        .await
        .map_err(|e| anyhow::anyhow!("the agent's pipe: {e:?}"))
}

/// How many clients the agent serves at once; one more is let go after its
/// handshake.
pub const MAX_SESSIONS: usize = 16;

/// Serves the agent on `listener`, a session per client, until the runtime stops.
pub async fn serve(listener: &Listener, agent: Arc<Local>) -> Result<()> {
    let mut acceptor = SessionAcceptor::new(listener, HandshakeMode::version_only(), PROTOCOL);
    let attached = Rc::new(Cell::new(0usize));

    loop {
        let peer = Rc::new(Cell::new(None));
        let session = acceptor
            .next::<windows_agent::Client, _>(AgentImpl::new(agent.clone(), peer.clone()))
            .await
            .map_err(|e| anyhow::anyhow!("the agent's pipe stopped accepting: {e:?}"))?;
        if attached.get() >= MAX_SESSIONS {
            tracing::warn!("a client let go: {MAX_SESSIONS} sessions are open already");
            continue;
        }
        peer.set(session.peer_version());
        attached.set(attached.get() + 1);
        agent.set_attached(true);

        let agent = agent.clone();
        let attached = attached.clone();
        compio::runtime::spawn(async move {
            if let Err(e) = session.wait().await {
                tracing::warn!("rpc session ended: {e:?}");
            }
            attached.set(attached.get() - 1);
            if attached.get() == 0 {
                agent.set_attached(false);
            }
        })
        .detach();
    }
}
