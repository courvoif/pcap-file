//! Parsing, reading, and writing pcapng files.
//!
//! Use [`PcapNgParser`] to parse pcapng data from byte slices, [`PcapNgReader`]
//! to read pcapng data from an I/O stream, [`PcapNgPacketIterator`] for simple
//! iteration over owned packets, and [`PcapNgWriter`] to write pcapng data.
//! Error types are available in the [`errors`] module.
//!
//! This implementation targets
//! [draft-ietf-opsawg-pcapng-05](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html#name-interface-description-block).
//! Unsupported block, record, and option types are preserved as unknown data when their framing is valid.

pub mod blocks;
pub mod errors;

pub use blocks::{Block, RawBlock};

pub(crate) mod state;
pub use state::PcapNgState;

pub(crate) mod parser;
pub use parser::*;

pub(crate) mod reader;
pub use reader::*;

pub(crate) mod packet;
pub use packet::*;

pub(crate) mod writer;
pub use writer::*;
