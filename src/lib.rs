#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case, non_camel_case_types)]

pub mod agent;
pub mod api;
pub mod embedded;
pub mod remote;

mod commands;
mod feed;
#[cfg(feature = "service")]
mod http;
#[cfg(feature = "service")]
mod logger;
mod monitor;
mod privileges;
mod profile;
#[cfg(feature = "service")]
mod rpc;
mod scm;
#[cfg(feature = "service")]
mod service;
mod win;

#[cfg(feature = "service")]
pub use logger::init_console;
#[cfg(feature = "service")]
pub use service::{install, run_as_service, run_direct, uninstall};
