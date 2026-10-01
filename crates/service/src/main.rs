mod logger;
mod service;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use uniproc_windows_agent::api::{SERVICE_DISPLAY_NAME, SERVICE_NAME};

const SERVICE_DESC: &str = "Provides system monitoring (processes, disk I/O, network, CPU) \
                               and exposes control primitives for process and Windows management \
                               on behalf of the Uniproc application";

#[derive(Parser)]
#[command(
    name = "uniproc_monitor",
    about = "Uniproc System Monitor Service",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Install the Windows service
    Install,
    /// Uninstall the Windows service
    Uninstall,
    /// Run directly in the console
    Run,
}

#[cfg(debug_assertions)]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> Result<()> {
    #[cfg(debug_assertions)]
    let _profiler = dhat::Profiler::new_heap();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Install) => {
            service::install(SERVICE_NAME, SERVICE_DISPLAY_NAME, SERVICE_DESC)
                .context("Failed to install service")?;
            println!("[+] Service installed successfully.");
        }
        Some(Command::Uninstall) => {
            service::uninstall(SERVICE_NAME).context("Failed to uninstall service")?;
            println!("[+] Service uninstalled successfully.");
        }
        Some(Command::Run) => {
            service::run_direct(logger::init())?;
        }
        None => {
            service::run_as_service()?;
        }
    }

    Ok(())
}
