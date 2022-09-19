#![allow(clippy::unreadable_literal)]

//! Provides parsers, readers and writers for Pcap and PcapNg files.
//!
//! For Pcap files see
//! [PcapParser](struct.PcapParser.html), [PcapReader](struct.PcapReader.html) and [PcapWriter](struct.PcapWriter.html).
//!
//! For PcapNg files see
//! [PcapNgParser](struct.PcapNgParser.html), [PcapNgReader](struct.PcapNgReader.html) and [PcapNgWriter](struct.PcapNgWriter.html).


pub use common::*;
pub use errors::*;
pub use pcap::{PcapParser, PcapReader, PcapWriter};
pub use pcapng::{PcapNgBlock, PcapNgParser, PcapNgReader, PcapNgWriter};

pub(crate) mod common;
pub(crate) mod errors;
pub(crate) mod read_buffer;

pub mod pcap;
pub mod pcapng;
