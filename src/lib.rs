//! Contains all the materials needed to read and write a pcap file format.
//!
//! Provides two structs, `PcapReader` and `PcapWriter`, to read and write Pcap.
//!
//! Provides a `Packet` which contains all the data relative to one packet
//!
//! # Examples
//!
//! ```rust,no_run
//! use std::fs::File;
//! use pcap_file::{PcapReader, PcapWriter};
//!
//! let file_in = File::open("test.pcap").expect("Error opening file");
//! let pcap_reader = PcapReader::new(file_in).unwrap();
//!
//! let file_out = File::create("out.pcap").expect("Error creating file");
//! let mut pcap_writer = PcapWriter::new(file_out).unwrap();
//!
//! // Read test.pcap
//! for pcap in pcap_reader {
//!     //Write each packet of test.pcap in out.pcap
//!     pcap_writer.write_packet(&pcap).unwrap();
//! }
//!
//! ```
extern crate byteorder;

#[macro_use]
extern crate error_chain;

pub mod errors;

pub mod packet;
pub use packet::Packet;

pub mod pcap_header;

pub mod reader;
pub use reader::PcapReader;

pub mod writer;
pub use writer::PcapWriter;
