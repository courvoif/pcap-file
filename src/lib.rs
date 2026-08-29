#![allow(clippy::unreadable_literal)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

//! Provides parsers, readers, and writers for pcap and pcapng files.
//!
//! For pcap files, see the [`pcap`] module, especially [`PcapParser`](pcap::PcapParser),
//! [`PcapReader<R>`](pcap::PcapReader) and [`PcapWriter<W>`](pcap::PcapWriter).
//!
//! For pcapng files, see the [`pcapng`] module, especially [`PcapNgParser`](pcapng::PcapNgParser),
//! [`PcapNgReader<R>`](pcapng::PcapNgReader), and [`PcapNgWriter<W>`](pcapng::PcapNgWriter).

pub use common::*;

pub(crate) mod common;
pub(crate) mod read_buffer;

pub mod pcap;
pub mod pcapng;
