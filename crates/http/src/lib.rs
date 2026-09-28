//! A window into what the agent publishes, for people rather than clients:
//! it reads the feed and the agent's spans, and changes nothing but the log
//! filter. One thread with its own tokio runtime; it shares nothing with the
//! capnp side but the feed.

mod telemetry;

pub use telemetry::{Cost, Spans, Telemetry};

use std::collections::HashMap;
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
use tracing_subscriber::EnvFilter;

use uniproc_windows_agent::api::{
    MachineMetrics, MachineSample, MetricSpec, ProcessMetric, ProcessState, SmolStr,
};
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
    states_etag: u64,
    services_etag: u64,
    dropped_by_sink: u64,
    sample: SampleHeader,
    machine: MachineSample,
    rows: Vec<Row>,
}

#[derive(Serialize)]
struct SampleHeader {
    snapshot: u64,
    sampled_at: u64,
    period_ms: u64,
    processes: Vec<String>,
    machine: Vec<String>,
}

#[derive(Serialize)]
struct Row {
    pid: u32,
    parent_pid: u32,
    sequence_number: u64,
    name: SmolStr,
    display_name: SmolStr,
    image_path: SmolStr,
    cmdline_args: usize,
    user: SmolStr,
    publisher: SmolStr,
    architecture: String,
    elevated: Option<bool>,
    isolation: String,
    is_service: bool,
    is_kernel_process: bool,
    is_windows_process: bool,
    signature: String,
    suspended: Option<bool>,
    efficiency_mode: Option<bool>,
    base_priority: Option<String>,
    io_priority: String,
    cpu_user_time: Option<u64>,
    cpu_kernel_time: Option<u64>,
    working_set: Option<u64>,
    private_working_set: Option<u64>,
    commit: Option<u64>,
    handles: Option<u32>,
    threads: Option<u32>,
    io_read_bytes: Option<u64>,
    io_write_bytes: Option<u64>,
    net_rx_bytes: Option<u64>,
    net_tx_bytes: Option<u64>,
}

fn cell<T: Copy>(column: &Option<Arc<[T]>>, row: Option<usize>) -> Option<T> {
    column.as_ref()?.get(row?).copied()
}

const SHOWN: [ProcessMetric; 11] = [
    ProcessMetric::CpuUserTime,
    ProcessMetric::CpuKernelTime,
    ProcessMetric::WorkingSet,
    ProcessMetric::PrivateWorkingSet,
    ProcessMetric::Commit,
    ProcessMetric::Handles,
    ProcessMetric::Threads,
    ProcessMetric::IoReadBytes,
    ProcessMetric::IoWriteBytes,
    ProcessMetric::NetRxBytes,
    ProcessMetric::NetTxBytes,
];

/// Nothing is sampled for nobody: a request subscribes for as long as it waits.
const SAMPLE_WAIT: Duration = Duration::from_secs(3);

struct App {
    agent: Arc<Local>,
    telemetry: Telemetry,
}

async fn snapshot(State(app): State<Arc<App>>) -> Json<Snapshot> {
    let agent = &app.agent;
    let sampler = agent.subscribe(MetricSpec {
        interval: Duration::from_secs(1),
        processes: SHOWN.into_iter().collect(),
        machine: MachineMetrics::all(),
    });
    let sample = tokio::time::timeout(SAMPLE_WAIT, sampler.sample(0))
        .await
        .unwrap_or_default();
    drop(sampler);
    let latest = agent.latest();
    let s = &latest.snapshot;
    let c = &sample.columns;

    let sampled: HashMap<(u32, u64), usize> = sample
        .pids
        .iter()
        .zip(sample.sequence_numbers.iter())
        .enumerate()
        .map(|(i, (&pid, &sequence_number))| ((pid, sequence_number), i))
        .collect();
    let states: HashMap<(u32, u64), &ProcessState> = s
        .states
        .value
        .states
        .iter()
        .map(|state| ((state.pid, state.sequence_number), state))
        .collect();

    let rows = s
        .processes
        .value
        .iter()
        .map(|p| {
            let key = (p.pid, p.sequence_number);
            let at = sampled.get(&key).copied();
            let state = states.get(&key).copied().copied().unwrap_or_default();
            Row {
                pid: p.pid,
                parent_pid: p.parent_pid,
                sequence_number: p.sequence_number,
                name: p.name.clone(),
                display_name: p.display_name.clone(),
                image_path: p.image_path.clone(),
                cmdline_args: p.cmdline.len(),
                user: p.user.clone(),
                publisher: p.publisher.clone(),
                architecture: format!("{:?}", p.architecture),
                elevated: p.elevated,
                isolation: format!("{:?}", p.isolation),
                is_service: p.is_service,
                is_kernel_process: p.is_kernel_process,
                is_windows_process: p.is_windows_process,
                signature: format!("{:?}", p.signature),
                suspended: state.suspended,
                efficiency_mode: state.efficiency_mode,
                base_priority: state.base_priority.map(|p| format!("{p:?}")),
                io_priority: format!("{:?}", state.io_priority),
                cpu_user_time: cell(&c.cpu_user_time, at),
                cpu_kernel_time: cell(&c.cpu_kernel_time, at),
                working_set: cell(&c.working_set, at),
                private_working_set: cell(&c.private_working_set, at),
                commit: cell(&c.commit, at),
                handles: cell(&c.handles, at),
                threads: cell(&c.threads, at),
                io_read_bytes: cell(&c.io_read_bytes, at),
                io_write_bytes: cell(&c.io_write_bytes, at),
                net_rx_bytes: cell(&c.net_rx_bytes, at),
                net_tx_bytes: cell(&c.net_tx_bytes, at),
            }
        })
        .collect();

    Json(Snapshot {
        processes: s.processes.value.len(),
        services: s.services.value.len(),
        processes_etag: s.processes.etag,
        states_etag: s.states.etag,
        services_etag: s.services.etag,
        dropped_by_sink: latest.dropped_by_sink,
        sample: SampleHeader {
            snapshot: sample.snapshot,
            sampled_at: sample.sampled_at,
            period_ms: sample.period.as_millis() as u64,
            processes: sample.wanted.processes.iter().map(|m| format!("{m:?}")).collect(),
            machine: sample.wanted.machine.iter().map(|m| format!("{m:?}")).collect(),
        },
        machine: sample.machine,
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
    snapshot_error: Option<String>,
    costs: Vec<SpanCost>,
}

/// How long a span of the agent stays entered, over every time it ran.
#[derive(Serialize)]
struct SpanCost {
    name: &'static str,
    runs: u64,
    last_us: u64,
    mean_us: u64,
    max_us: u64,
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

async fn health(State(app): State<Arc<App>>) -> (StatusCode, Json<Health>) {
    let latest = app.agent.latest();
    let age = latest.reported_at.map(|at| at.elapsed());
    let ok = age.is_some_and(|age| age < STALE)
        && !latest.sessions.is_empty()
        && latest.sessions.iter().all(|s| s.is_healthy())
        && latest.snapshot_error.is_none();
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
        snapshot_error: latest.snapshot_error.clone(),
        costs: app
            .telemetry
            .spans
            .costs()
            .into_iter()
            .map(|(name, cost)| SpanCost {
                name,
                runs: cost.runs,
                last_us: cost.last.as_micros() as u64,
                mean_us: cost.mean.as_micros() as u64,
                max_us: cost.max.as_micros() as u64,
            })
            .collect(),
    };
    let status = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(health))
}

async fn log_filter(State(app): State<Arc<App>>) -> (StatusCode, String) {
    match app.telemetry.filter.with_current(|filter| filter.to_string()) {
        Ok(filter) => (StatusCode::OK, filter),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

/// Takes the body as `RUST_LOG` directives for the log from now on.
async fn set_log_filter(State(app): State<Arc<App>>, directives: String) -> (StatusCode, String) {
    let filter = match EnvFilter::try_new(directives.trim()) {
        Ok(filter) => filter,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()),
    };
    let shown = filter.to_string();
    match app.telemetry.filter.reload(filter) {
        Ok(()) => {
            tracing::info!(filter = %shown, "the log filter changed");
            (StatusCode::OK, shown)
        }
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
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

pub fn serve(agent: Arc<Local>, telemetry: Telemetry) -> io::Result<Access> {
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
        .route("/log", get(log_filter).put(set_log_filter))
        .layer(axum::middleware::from_fn(move |request, next| {
            authorized(expected.clone(), request, next)
        }))
        .with_state(Arc::new(App { agent, telemetry }));

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
