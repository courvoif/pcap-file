//! Parsing, reading, and writing pcapng files.
//!
//! Use [`PcapNgParser`] to parse pcapng data from byte slices, [`PcapNgReader`] to read pcapng data from an I/O stream,
//! [`PcapNgWriter`] to write pcapng data and [`PcapNgPacketIterator`] for iteration over owned packets.

pub mod blocks;
pub mod errors;

pub(crate) mod state;
pub use state::PcapNgState;

pub(crate) mod parser;
pub use parser::PcapNgParser;

pub(crate) mod reader;
pub use reader::{PcapNgPacket, PcapNgPacketIterator, PcapNgReader};

pub(crate) mod writer;
pub use writer::PcapNgWriter;
