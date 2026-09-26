#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case, non_camel_case_types)]

pub mod agent;
pub mod api;
pub mod embedded;
pub mod remote;
pub mod wire;

mod commands;
mod feed;
mod monitor;
mod privileges;
mod profile;
mod scm;
mod win;
