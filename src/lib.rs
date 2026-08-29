#![allow(clippy::unreadable_literal)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub use common::*;

pub(crate) mod common;
pub(crate) mod read_buffer;

pub mod pcap;
pub mod pcapng;
