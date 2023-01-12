#![allow(clippy::unreadable_literal)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub use common::*;
pub use errors::*;

pub(crate) mod common;
pub(crate) mod errors;
pub(crate) mod read_buffer;

pub mod pcap;
pub mod pcapng;
