#![allow(clippy::unreadable_literal)]
#![warn(missing_docs)]
#![doc = concat!(include_str!("rustdoc_links.md"), include_str!("../README.md"))]

/* ----- Public exports ----- */

pub use common::*;

/* ----- Modules ----- */

pub(crate) mod common;
pub(crate) mod read_buffer;

pub mod pcap;
pub mod pcapng;
