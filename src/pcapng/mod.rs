//! Parsing, reading, and writing pcapng files.
//!
//! Use [`PcapNgParser`] to parse pcapng data from byte slices, [`PcapNgReader`]
//! to read pcapng data from an I/O stream, [`PcapNgPacketIterator`] for simple
//! iteration over owned packets, and [`PcapNgWriter`] to write pcapng data.

pub mod blocks;
pub mod errors;

pub(crate) mod state;
pub use state::PcapNgState;

pub(crate) mod parser;
pub use parser::PcapNgParser;

pub(crate) mod reader;
pub use reader::{PcapNgPacketIterator, PcapNgReader};

pub(crate) mod packet;
pub use packet::PcapNgPacket;

pub(crate) mod writer;
pub use writer::PcapNgWriter;
