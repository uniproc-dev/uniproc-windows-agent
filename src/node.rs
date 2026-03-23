use anyhow::Result;
use ogurpchik::discovery::Scope;
use ogurpchik::high::node::Node;
use ogurpchik::high::service_handler::ServiceHandler;
use ogurpchik::transport::stream::adapters::uds::UdsTransport;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uniproc_protocol::{
    ArchivedWindowsRequest, WindowsCodec, WindowsMachineStats, WindowsReport, WindowsResponse,
    services,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

use crate::collector::settings::CollectorSettings;
use crate::collector::state::ProcessEntry;
use crate::monitor::SharedCollector;
use crate::commands;

#[derive(Clone)]
pub struct WindowsHandler {
    collector: SharedCollector,
    settings: CollectorSettings,
}

impl ServiceHandler<WindowsCodec> for WindowsHandler {
    async fn on_request<'a>(&self, req: &ArchivedWindowsRequest) -> Result<WindowsResponse> {
        match req {
            ArchivedWindowsRequest::GetReport => {
                let report = build_report(&self.collector.lock().unwrap().processes());
                Ok(WindowsResponse::Report(report))
            }
            ArchivedWindowsRequest::Ping => Ok(WindowsResponse::Pong),
            ArchivedWindowsRequest::SetConfig(cfg) => {
                if cfg.memory_interval_ms > 0 {
                    self.settings.set_interval(Duration::from_millis(cfg.memory_interval_ms.into()));
                }
                if cfg.cpu_interval_ms > 0 {
                    self.settings.set_interval(Duration::from_millis(cfg.cpu_interval_ms.into()));
                }
                Ok(WindowsResponse::ConfigApplied)
            }
            ArchivedWindowsRequest::ProcessCommand(cmd) => {
                Ok(WindowsResponse::CommandResult(commands::execute(cmd)))
            }
        }
    }
}

fn build_machine_stats(processes: &[ProcessEntry]) -> WindowsMachineStats {
    let mut stats = WindowsMachineStats::default();

    let mut mem = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut mem) }.is_ok() {
        stats.total_physical_kb = mem.ullTotalPhys / 1024;
        stats.available_physical_kb = mem.ullAvailPhys / 1024;
        stats.used_physical_kb = (mem.ullTotalPhys - mem.ullAvailPhys) / 1024;
    }

    for p in processes {
        stats.disk_read_bytes += p.disk.read_bytes;
        stats.disk_write_bytes += p.disk.write_bytes;
        stats.disk_read_iops += p.disk.read_ops;
        stats.disk_write_iops += p.disk.write_ops;
        stats.net_rx_bytes += p.network.recv_bytes;
        stats.net_tx_bytes += p.network.sent_bytes;
    }

    stats
}

fn build_report(processes: &[ProcessEntry]) -> WindowsReport {
    use uniproc_protocol::WindowsProcessStats;

    WindowsReport {
        machine: build_machine_stats(processes),
        processes: processes
            .iter()
            .map(|e| {
                let mut name = [0u8; 64];
                let b = e.image_name.as_bytes();
                name[..b.len().min(63)].copy_from_slice(&b[..b.len().min(63)]);

                let mut cmdline = [0u8; 256];
                let b = e.command_line.as_bytes();
                cmdline[..b.len().min(255)].copy_from_slice(&b[..b.len().min(255)]);

                let mem = e.memory.as_ref();

                WindowsProcessStats {
                    pid: e.pid,
                    parent_pid: e.parent_pid,
                    session_id: e.session_id,
                    name,
                    cmdline,
                    cpu_percent: e.cpu.total_percent as f32,
                    working_set_kb: mem.map(|m| m.working_set_bytes / 1024).unwrap_or(0),
                    private_bytes_kb: mem.map(|m| m.private_bytes / 1024).unwrap_or(0),
                    peak_working_set_kb: mem.map(|m| m.peak_working_set_bytes / 1024).unwrap_or(0),
                    disk_read_bytes: e.disk.read_bytes,
                    disk_write_bytes: e.disk.write_bytes,
                    disk_read_iops: e.disk.read_ops,
                    disk_write_iops: e.disk.write_ops,
                    net_rx_bytes: e.network.recv_bytes,
                    net_tx_bytes: e.network.sent_bytes,
                }
            })
            .collect(),
    }
}

pub async fn run(collector: SharedCollector) -> Result<()> {
    let settings = collector.lock().unwrap().settings();

    let _guard = Node::new()?
        .scope(Scope::Internal)?
        .serve::<WindowsCodec, _, _>(
            UdsTransport::temp("uniproc-windows"),
            WindowsHandler { collector, settings },
        )
        .publish(services::WINDOWS_AGENT)
        .start()
        .await?;

    futures::future::pending::<()>().await;
    Ok(())
}
