#![allow(clippy::unreadable_literal)]

//! This crate contains parsers and readers for Pcap and Pcapng files.
//! It also contains a writer for Pcap files.
//!
//! For Pcap files see
//! [PcapReader](struct.PcapReader.html), [PcapParser](struct.PcapParser.html) and [PcapWriter](struct.PcapParser.html)
//!
//! For PcapNg files see
//! [PcapNgReader](struct.PcapNgReader.html) and [PcapParser](struct.PcapParser.html)

pub(crate) mod common;
pub use common::*;

pub(crate) mod errors;
pub use errors::*;

pub mod pcap;
pub use pcap::{PcapReader, PcapParser, PcapWriter};

pub mod pcapng;
pub use pcapng::{PcapNgReader, PcapNgParser};

pub(crate) mod peek_reader;