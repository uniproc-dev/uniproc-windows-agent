#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case, non_camel_case_types)]

pub mod api;

mod aligned;
mod commands;
mod etw;
mod http;
mod logger;
mod monitor;
mod privileges;
mod providers;
mod rpc;
mod service;
mod settings;
mod sink;
mod state;
mod supervisor;
mod win;

pub use commands::cpu::run as print_cpu;
pub use logger::init_console;
pub use service::{install, run_as_service, run_direct, uninstall};
