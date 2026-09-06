//! Parsing, reading, and writing pcap files.
//!
//! Use [`PcapParser`] to parse pcap data from byte slices , [`PcapReader`] to read pcap data from an I/O stream,
//! [`PcapPacketIterator`] for simple iteration over owned packets and [`PcapWriter`] to write pcap data.

mod errors;
mod header;
mod packet;
mod parser;
mod reader;
pub(crate) mod utils;
mod writer;

pub use errors::*;
pub use header::*;
pub use packet::*;
pub use parser::*;
pub use reader::*;
pub use utils::*;
pub use writer::*;
