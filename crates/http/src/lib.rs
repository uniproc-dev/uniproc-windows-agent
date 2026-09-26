//! A read-only window into what the agent publishes, for people rather than clients.
//! One thread with its own tokio runtime; it shares nothing with the capnp side but the feed.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};

use uniproc_windows_agent::local::Local;

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

#[derive(Serialize)]
struct Snapshot {
    processes: usize,
    services: usize,
    processes_etag: u64,
    services_etag: u64,
    dropped_by_sink: u64,
    samples: Samples,
    machine: Machine,
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
    cpu_percent: f32,
    working_set_kb: u64,
    private_bytes_kb: u64,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
    is_service: bool,
    is_kernel_process: bool,
    is_windows_process: bool,
    signature: String,
}

async fn snapshot(State(agent): State<Arc<Local>>) -> Json<Snapshot> {
    let latest = agent.latest();
    let s = &latest.snapshot;
    let m = &s.machine;

    let rows = s
        .processes
        .value
        .iter()
        .zip(&s.metrics)
        .map(|(p, metrics)| Row {
            pid: p.pid,
            parent_pid: p.parent_pid,
            name: p.name.clone(),
            display_name: p.display_name.clone(),
            image_path: p.image_path.clone(),
            cmdline_args: p.cmdline.len(),
            cpu_percent: metrics.cpu_percent,
            working_set_kb: metrics.working_set_kb,
            private_bytes_kb: metrics.private_bytes_kb,
            disk_read_bytes: metrics.disk_read_bytes,
            disk_write_bytes: metrics.disk_write_bytes,
            net_rx_bytes: metrics.net_rx_bytes,
            net_tx_bytes: metrics.net_tx_bytes,
            is_service: p.is_service,
            is_kernel_process: p.is_kernel_process,
            is_windows_process: p.is_windows_process,
            signature: format!("{:?}", p.signature),
        })
        .collect();

    Json(Snapshot {
        processes: s.processes.value.len(),
        services: s.services.value.len(),
        processes_etag: s.processes.etag,
        services_etag: s.services.etag,
        dropped_by_sink: latest.dropped_by_sink,
        samples: Samples {
            attributed: latest.samples.attributed,
            unattributed: latest.samples.unattributed,
            idle: latest.samples.idle,
        },
        machine: Machine {
            total_physical_kb: m.total_physical_kb,
            available_physical_kb: m.available_physical_kb,
            used_physical_kb: m.used_physical_kb,
            cpu_percent: m.cpu_percent,
            cpu_max_mhz: m.cpu_max_mhz,
            cpu_current_mhz: m.cpu_current_mhz,
            cpu_interrupt_percent: m.cpu_interrupt_percent,
            cpu_dpc_percent: m.cpu_dpc_percent,
        },
        totals: Totals {
            disk_read_bytes: m.disk_read_bytes,
            disk_write_bytes: m.disk_write_bytes,
            disk_read_ops: m.disk_read_iops,
            disk_write_ops: m.disk_write_iops,
            net_rx_bytes: m.net_rx_bytes,
            net_tx_bytes: m.net_tx_bytes,
        },
        rows,
    })
}

/// The core reports at least once a second; a report older than this means it stalled.
const STALE: Duration = Duration::from_secs(5);

#[derive(Serialize)]
struct Health {
    ok: bool,
    report_age_ms: Option<u64>,
    dropped_by_sink: u64,
    sessions: Vec<Session>,
}

#[derive(Serialize)]
struct Session {
    name: String,
    running: bool,
    pumping: bool,
    events_lost: u32,
    realtime_buffers_lost: u32,
    log_buffers_lost: u32,
    buffers_written: u32,
    buffers: u32,
    free_buffers: u32,
}

async fn health(State(agent): State<Arc<Local>>) -> (StatusCode, Json<Health>) {
    let latest = agent.latest();
    let age = latest.reported_at.map(|at| at.elapsed());
    let ok = age.is_some_and(|age| age < STALE)
        && !latest.sessions.is_empty()
        && latest.sessions.iter().all(|s| s.is_healthy());
    let health = Health {
        ok,
        report_age_ms: age.map(|age| age.as_millis() as u64),
        dropped_by_sink: latest.dropped_by_sink,
        sessions: latest
            .sessions
            .iter()
            .map(|s| Session {
                name: s.name.clone(),
                running: s.running,
                pumping: s.pumping,
                events_lost: s.events_lost,
                realtime_buffers_lost: s.realtime_buffers_lost,
                log_buffers_lost: s.log_buffers_lost,
                buffers_written: s.buffers_written,
                buffers: s.buffers,
                free_buffers: s.free_buffers,
            })
            .collect(),
    };
    let status = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(health))
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

pub fn serve(agent: Arc<Local>) -> io::Result<Access> {
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
        .with_state(agent);

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
