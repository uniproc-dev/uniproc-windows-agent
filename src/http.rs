//! A read-only window into what the agent holds.
//!
//! The RPC report says what a client is meant to see; this says what the
//! state actually contains, which is what tells a wrong report from an empty
//! one. Serving it costs one thread with its own tokio runtime - the capnp
//! side keeps compio and the two share nothing but the state behind its lock.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::monitor::SharedSupervisor;
use crate::state::SystemState;

/// Where it listens unless `UNIPROC_AGENT_HTTP` says otherwise; any free port
/// when this one is taken.
const PREFERRED: &str = "127.0.0.1:47386";

/// Where it answers and what it wants, written where the agent's own data
/// lives: whoever cannot read that directory cannot ask.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Access {
    pub url: String,
    pub token: String,
}

pub fn access_path() -> PathBuf {
    let root = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    root.join("Uniproc").join("agent.http.json")
}

impl Access {
    fn write(&self) -> io::Result<()> {
        let path = access_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        std::fs::write(path, text)
    }
}

#[derive(Clone)]
struct Api {
    state: Arc<Mutex<SystemState>>,
    supervisor: SharedSupervisor,
}

#[derive(Serialize)]
struct Snapshot {
    processes: usize,
    services: usize,
    dropped_by_sink: u64,
    samples: Samples,
    machine: Option<Machine>,
    totals: Totals,
    rows: Vec<Row>,
}

#[derive(Serialize)]
struct Samples {
    attributed: u64,
    unattributed: u64,
    idle: u64,
}

#[derive(Serialize)]
struct Machine {
    total_physical_kb: u64,
    available_physical_kb: u64,
    used_physical_kb: u64,
    cpu_percent: f32,
    cpu_max_mhz: u64,
    cpu_current_mhz: u64,
    cpu_interrupt_percent: f32,
    cpu_dpc_percent: f32,
}

#[derive(Serialize)]
struct Totals {
    disk_read_bytes: u64,
    disk_write_bytes: u64,
    disk_read_ops: u64,
    disk_write_ops: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
}

#[derive(Serialize)]
struct Row {
    pid: u32,
    parent_pid: u32,
    name: String,
    display_name: String,
    image_path: String,
    cmdline_args: usize,
    cpu_percent: f64,
    working_set_kb: u64,
    private_bytes_kb: u64,
    memory_age_ms: Option<u64>,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
    exited: bool,
    is_service: bool,
    is_kernel_process: bool,
    is_windows_process: bool,
    signature: String,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn snapshot(State(api): State<Api>) -> Json<Snapshot> {
    // Lock order matters: the tick thread holds the supervisor while it takes
    // the state, so this reads the supervisor first and lets it go before
    // taking the state. Nesting them the other way round would deadlock.
    let dropped_by_sink = api.supervisor.lock().dropped();

    let state = api.state.lock();
    let now = now_ms();
    let (attributed, unattributed, idle) = state.sample_counts();

    let rows = state
        .entries()
        .map(|e| Row {
            pid: e.pid,
            parent_pid: e.parent_pid,
            name: e.image_name.clone(),
            display_name: e.display_name.clone(),
            image_path: e.image_path.clone(),
            cmdline_args: e.command_line.len(),
            cpu_percent: e.cpu.total_percent,
            working_set_kb: e.memory.as_ref().map(|m| m.working_set_bytes / 1024).unwrap_or(0),
            private_bytes_kb: e.memory.as_ref().map(|m| m.private_bytes / 1024).unwrap_or(0),
            memory_age_ms: e.memory.as_ref().map(|m| now.saturating_sub(m.timestamp_ms)),
            disk_read_bytes: e.disk.read_bytes,
            disk_write_bytes: e.disk.write_bytes,
            net_rx_bytes: e.network.recv_bytes,
            net_tx_bytes: e.network.sent_bytes,
            exited: e.exited,
            is_service: state.is_service(e.pid),
            is_kernel_process: e.is_kernel_process,
            is_windows_process: e.is_windows_process,
            signature: format!("{:?}", e.signature),
        })
        .collect();

    let totals = state.machine_totals();
    let snapshot = Snapshot {
        processes: state.len(),
        services: state.services().len(),
        dropped_by_sink,
        samples: Samples {
            attributed,
            unattributed,
            idle,
        },
        machine: state.machine().map(|m| Machine {
            total_physical_kb: m.total_physical_kb,
            available_physical_kb: m.available_physical_kb,
            used_physical_kb: m.used_physical_kb,
            cpu_percent: m.cpu_percent,
            cpu_max_mhz: m.cpu_max_mhz,
            cpu_current_mhz: m.cpu_current_mhz,
            cpu_interrupt_percent: m.cpu_interrupt_percent,
            cpu_dpc_percent: m.cpu_dpc_percent,
        }),
        totals: Totals {
            disk_read_bytes: totals.disk_read_bytes,
            disk_write_bytes: totals.disk_write_bytes,
            disk_read_ops: totals.disk_read_ops,
            disk_write_ops: totals.disk_write_ops,
            net_rx_bytes: totals.net_rx_bytes,
            net_tx_bytes: totals.net_tx_bytes,
        },
        rows,
    };
    drop(state);

    Json(snapshot)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

fn token() -> io::Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn bind() -> io::Result<(TcpListener, SocketAddr)> {
    let wanted = std::env::var("UNIPROC_AGENT_HTTP").unwrap_or_else(|_| PREFERRED.to_string());
    let listener = TcpListener::bind(&wanted).or_else(|_| TcpListener::bind("127.0.0.1:0"))?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

async fn authorized(expected: Arc<str>, request: Request, next: Next) -> Response {
    let carried = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    if carried != Some(&*expected) {
        let said = serde_json::json!({ "error": "missing or wrong bearer token" });
        return (StatusCode::UNAUTHORIZED, Json(said)).into_response();
    }

    next.run(request).await
}

pub fn serve(state: Arc<Mutex<SystemState>>, supervisor: SharedSupervisor) -> io::Result<Access> {
    let (listener, addr) = bind()?;
    listener.set_nonblocking(true)?;

    let access = Access {
        url: format!("http://{addr}"),
        token: token()?,
    };
    access.write()?;

    let expected: Arc<str> = format!("Bearer {}", access.token).into();
    let app = axum::Router::new()
        .route("/state", get(snapshot))
        .route("/health", get(health))
        .layer(axum::middleware::from_fn(move |request, next| {
            authorized(expected.clone(), request, next)
        }))
        .with_state(Api { state, supervisor });

    std::thread::Builder::new()
        .name("agent-http".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => return tracing::error!(%error, "the state API has no runtime"),
            };

            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => return tracing::error!(%error, "the state API cannot listen"),
                };

                if let Err(error) = axum::serve(listener, app).await {
                    tracing::error!(%error, "the state API stopped");
                }
            });
        })?;

    Ok(access)
}
