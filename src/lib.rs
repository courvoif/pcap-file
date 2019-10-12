#![allow(clippy::unreadable_literal)]

//! Provides two structs, `PcapReader` and `PcapWriter`, to read and write Pcap.
//!
//! Also provides a `Packet` struct which represents a pcap packet with its header.
//!
//! # Examples
//!
//! ```no_run
//! use std::fs::File;
//! use pcap_file::pcap::{PcapReader, PcapWriter};
//!
//! let file_in = File::open("test.pcap").expect("Error opening file");
//! let pcap_reader = PcapReader::new(file_in).unwrap();
//!
//! let file_out = File::create("out.pcap").expect("Error creating file");
//! let mut pcap_writer = PcapWriter::new(file_out).unwrap();
//!
//! // Read test.pcap
//! for pcap in pcap_reader {
//!
//!     //Check if there is no error
//!     let pcap = pcap.unwrap();
//!
//!     //Write each packet of test.pcap in out.pcap
//!     pcap_writer.write_packet(&pcap).unwrap();
//! }
//!
//! ```

pub(crate) mod common;
pub use common::*;

pub(crate) mod errors;
pub use errors::*;

pub mod pcap;
pub mod pcapng;

pub(crate) mod peek_reader;