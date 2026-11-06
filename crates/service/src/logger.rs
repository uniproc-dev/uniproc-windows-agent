use std::sync::Mutex;
use std::os::windows::io::AsRawHandle;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt, reload};
use uniproc_windows_agent::data;
use uniproc_windows_http::{Spans, Telemetry};
use crate::bindings::{HANDLE, STD_ERROR_HANDLE, SetStdHandle};

/// Logs to the console.
pub fn init() -> Telemetry {
    with_writer(BoxMakeWriter::new(std::io::stdout), true)
}

/// Logs to `agent.log` in the agent's directory; the previous run's log is
/// kept as `agent.previous.log`. A service has no console, so without the
/// directory the log goes nowhere.
pub fn init_service() -> Telemetry {
    match log_file() {
        Ok(file) => {
            let redirected = redirect_stderr(&file);
            if std::env::var_os("RUST_BACKTRACE").is_none() {
                unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
            }
            let telemetry = with_writer(BoxMakeWriter::new(Mutex::new(file)), false);
            if let Err(error) = redirected {
                tracing::warn!(%error, "fatal diagnostics could not be redirected to the service log");
            }
            telemetry
        }
        Err(_) => with_writer(BoxMakeWriter::new(std::io::sink), false),
    }
}

fn redirect_stderr(file: &std::fs::File) -> windows_core::Result<()> {
    unsafe { SetStdHandle(STD_ERROR_HANDLE, HANDLE(file.as_raw_handle())) }.ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    #[test]
    fn service_stderr_is_written_to_its_log() {
        const CHILD: &str = "UNIPROC_STDERR_PROBE";
        if let Some(path) = std::env::var_os(CHILD) {
            let file = std::fs::File::create(path).unwrap();
            redirect_stderr(&file).unwrap();
            eprintln!("service fatal diagnostic probe");
            return;
        }
        let path = std::env::temp_dir().join(format!("uniproc-service-stderr-{}.log", std::process::id()));
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "logger::tests::service_stderr_is_written_to_its_log", "--nocapture"])
            .env(CHILD, &path)
            .creation_flags(crate::bindings::CREATE_NO_WINDOW as u32)
            .output().unwrap();
        let logged = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(result.status.success(), "{result:?}");
        assert_eq!(logged, "service fatal diagnostic probe\n");
    }
}
