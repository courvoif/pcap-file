#![allow(clippy::unreadable_literal)]
#![deny(missing_docs)]

//! Provides parsers, readers and writers for Pcap and PcapNg files.
//!
//! For Pcap files see
//! [PcapParser](struct.PcapParser.html), [PcapReader](struct.PcapReader.html) and [PcapWriter](struct.PcapWriter.html).
//!
//! For PcapNg files see
//! [PcapNgParser](struct.PcapNgParser.html), [PcapNgReader](struct.PcapNgReader.html) and [PcapNgWriter](struct.PcapNgWriter.html).


pub use common::*;
pub use errors::*;

pub(crate) mod common;
pub(crate) mod errors;
pub(crate) mod read_buffer;

pub mod pcap;
pub mod pcapng;
