#![allow(unsafe_op_in_unsafe_fn)]

mod etw;
mod logger;
mod service;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

const SERVICE_NAME: &str = "EtwProcessMonitor";
const SERVICE_DISPLAY: &str = "ETW Process Monitor";
const SERVICE_DESC: &str = "Monitors process creation/termination via ETW";
const ETW_SESSION_NAME: &str = "EtwProcessMonitorSession";

#[derive(Parser)]
#[command(
    name = "etw_monitor",
    about = "ETW-based process monitor / Windows service",
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
    /// Run directly in the console (for development/debugging)
    Run,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Install) => {
            service::install(SERVICE_NAME, SERVICE_DISPLAY, SERVICE_DESC)
                .context("Failed to install service")?;
            println!("[+] Service installed successfully.");
        }
        Some(Command::Uninstall) => {
            service::uninstall(SERVICE_NAME).context("Failed to uninstall service")?;
            println!("[+] Service uninstalled successfully.");
        }
        Some(Command::Run) => {
            logger::init_console();
            service::run_direct(ETW_SESSION_NAME)?;
        }
        None => {
            service::run_as_service(SERVICE_NAME, ETW_SESSION_NAME)?;
        }
    }

    Ok(())
}