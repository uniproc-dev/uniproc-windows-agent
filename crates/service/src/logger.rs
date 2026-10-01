use std::sync::Mutex;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt, reload};
use uniproc_windows_agent::data;
use uniproc_windows_http::{Spans, Telemetry};

/// Logs to the console.
pub fn init() -> Telemetry {
    with_writer(BoxMakeWriter::new(std::io::stdout), true)
}

/// Logs to `agent.log` in the agent's directory; the previous run's log is
/// kept as `agent.previous.log`. A service has no console, so without the
/// directory the log goes nowhere.
pub fn init_service() -> Telemetry {
    match log_file() {
        Ok(file) => with_writer(BoxMakeWriter::new(Mutex::new(file)), false),
        Err(_) => with_writer(BoxMakeWriter::new(std::io::sink), false),
    }
}

fn log_file() -> std::io::Result<std::fs::File> {
    let previous = data::claim("agent.previous.log")?;
    let current = data::claim("agent.log")?;
    if current.exists() {
        let _ = std::fs::remove_file(&previous);
        std::fs::rename(&current, &previous)?;
    }
    std::fs::File::create(current)
}

fn with_writer(writer: BoxMakeWriter, ansi: bool) -> Telemetry {
    let (filter, handle) = reload::Layer::new(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let spans = Spans::default();
    let registry = tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(writer)
                .with_ansi(ansi)
                .with_span_events(FmtSpan::CLOSE)
                .with_target(false)
                .with_thread_ids(false)
                .with_filter(filter),
        )
        .with(spans.clone().with_filter(ours()));
    #[cfg(feature = "tracy")]
    let registry = registry.with(tracing_tracy::TracyLayer::default().with_filter(ours()));
    registry.init();
    Telemetry {
        spans,
        filter: handle,
    }
}

fn ours() -> Targets {
    Targets::new()
        .with_target("uniproc_windows_core", LevelFilter::DEBUG)
        .with_target("uniproc_windows_agent", LevelFilter::DEBUG)
}
