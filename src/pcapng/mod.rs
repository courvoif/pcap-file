//! Contains the PcapNg parser, reader and writer

/* ----- Modules and public API ----- */

pub mod blocks;
pub use blocks::{Block, PcapNgBlock, RawBlock};

pub(crate) mod errors;
pub use errors::*;

pub(crate) mod state;
pub use state::PcapNgState;

pub(crate) mod parser;
pub use parser::PcapNgParser;

pub(crate) mod reader;
pub use reader::{PcapNgPacketIterator, PcapNgReader};

mod packet;
pub use packet::PcapNgPacket;

pub(crate) mod writer;
pub use writer::PcapNgWriter;
