#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case, non_camel_case_types)]

pub mod agent;
pub mod api;
pub mod embedded;
pub mod remote;

mod aligned;
mod commands;
#[cfg(feature = "service")]
mod cpu_report;
mod etw;
#[cfg(feature = "service")]
mod http;
#[cfg(feature = "service")]
mod logger;
mod monitor;
mod privileges;
mod providers;
#[cfg(feature = "service")]
mod rpc;
#[cfg(feature = "service")]
mod service;
mod settings;
mod sink;
mod state;
mod supervisor;
mod win;

#[cfg(feature = "service")]
pub use cpu_report::run as print_cpu;
#[cfg(feature = "service")]
pub use logger::init_console;
#[cfg(feature = "service")]
pub use service::{install, run_as_service, run_direct, uninstall};
