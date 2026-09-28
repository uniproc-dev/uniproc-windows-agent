use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt, reload};
use uniproc_windows_http::{Spans, Telemetry};

pub fn init() -> Telemetry {
    let (filter, handle) = reload::Layer::new(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let spans = Spans::default();
    let registry = tracing_subscriber::registry()
        .with(
            fmt::layer()
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
