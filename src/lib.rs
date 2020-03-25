#![allow(clippy::unreadable_literal)]

//! This crate contains parsers and readers for Pcap and Pcapng files.
//! It also contains a writer for Pcap files.
//!
//! For Pcap files see
//! [PcapReader](struct.PcapReader.html), [PcapParser](struct.PcapParser.html) and [PcapWriter](struct.PcapWriter.html).
//!
//! For PcapNg files see
//! [PcapNgReader](struct.PcapNgReader.html) and [PcapNgParser](struct.PcapNgParser.html).

pub use common::*;
pub use errors::*;
pub use pcap::{PcapParser, PcapReader, PcapWriter};
pub use pcapng::{PcapNgParser, PcapNgReader, PcapNgWriter};

pub(crate) mod common;
pub(crate) mod errors;
pub mod pcap;
pub mod pcapng;
pub(crate) mod peek_reader;