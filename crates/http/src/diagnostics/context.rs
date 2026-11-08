use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub fn collect() -> Value {
    let result = run();
    match result {
        Ok(value) => value,
        Err(error) => {
            json!({"status":"error","source":"Windows CIM inventory","error":error.to_string()})
        }
    }
}

fn run() -> Result<Value, Box<dyn std::error::Error>> {
    let system = std::env::var_os("SystemRoot").ok_or("SystemRoot is missing")?;
    let exe =
        std::path::PathBuf::from(system).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut child = Command::new(exe)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("context.ps1"),
        ])
        .env(
            "UNIPROC_DIAGNOSTIC_SERVICE_PID",
            std::process::id().to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000)
        .spawn()?;
    let stdout = child.stdout.take().ok_or("inventory stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("inventory stderr unavailable")?;
    let output = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(8 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(1024 * 1024)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(45);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Windows inventory exceeded 45 seconds".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let bytes = output
        .join()
        .map_err(|_| "inventory output reader panicked")??;
    let errors = errors
        .join()
        .map_err(|_| "inventory error reader panicked")??;
    if !status.success() {
        return Err(String::from_utf8_lossy(&errors).into_owned().into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
