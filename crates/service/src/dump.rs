use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Summary,
    Text,
    Json,
}

#[derive(Args)]
pub struct Options {
    #[arg(long)]
    input: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "summary")]
    format: Format,
    #[arg(long, default_value_t = 3000)]
    duration_ms: u64,
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
    #[arg(long)]
    output: Option<PathBuf>,
}

pub fn run(options: Options) -> Result<()> {
    let Options {
        input,
        format,
        duration_ms,
        interval_ms,
        output,
    } = options;
    ensure!(
        (100..=10000).contains(&interval_ms),
        "interval-ms must be between 100 and 10000"
    );
    ensure!(
        duration_ms >= interval_ms
            && duration_ms <= 30000
            && duration_ms.div_ceil(interval_ms) <= 15,
        "duration-ms must cover an interval, at most 30 seconds and at most 16 samples"
    );
    let bytes = if let Some(input) = input {
        ensure!(
            std::fs::metadata(&input)?.len() <= 256 * 1024 * 1024,
            "Input report exceeds 256 MiB"
        );
        std::fs::read(input)?
    } else {
        let access: uniproc_windows_http::Access = serde_json::from_slice(&std::fs::read(uniproc_windows_http::access_path()).context("Cannot read service diagnostic access; run this command as an administrator on the monitored machine")?)?;
        let url: ureq::http::Uri = access.url.parse().context("Invalid diagnostic address")?;
        ensure!(
            url.scheme_str() == Some("http")
                && url
                    .host()
                    .is_some_and(|host| matches!(host, "127.0.0.1" | "[::1]" | "::1")),
            "Diagnostic access must point to a loopback HTTP address"
        );
        let client: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(150)))
            .max_redirects(0)
            .proxy(None)
            .build()
            .into();
        let address = format!(
            "{}/diagnostics?duration_ms={duration_ms}&interval_ms={interval_ms}",
            access.url.trim_end_matches('/')
        );
        let mut response = client
        .get(&address)
        .header("Authorization", format!("Bearer {}", access.token))
        .call()
        .context(
            "Service diagnostic request failed; the running service must support the dump command",
        )?;
        response
            .body_mut()
            .with_config()
            .limit(256 * 1024 * 1024)
            .read_to_vec()?
    };
    let report: serde_json::Value =
        serde_json::from_slice(&bytes).context("Invalid diagnostic JSON")?;
    let text = match format {
        Format::Json => serde_json::to_string_pretty(&report)?,
        Format::Summary => uniproc_windows_http::diagnostics::render(&report, false),
        Format::Text => uniproc_windows_http::diagnostics::render(&report, true),
    };
    if let Some(path) = output {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "Cannot create {} (existing reports are preserved)",
                    path.display()
                )
            })?;
        file.write_all(text.as_bytes())?;
        file.write_all(b"\n")?;
    } else {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        stdout.write_all(text.as_bytes())?;
        stdout.write_all(b"\n")?;
    }
    Ok(())
}
