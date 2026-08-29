//! Parsing, reading, and writing pcapng files.
//!
//! Use [`PcapNgParser`] to parse pcapng data from byte slices, [`PcapNgReader`] to read pcapng data from an I/O stream,
//! [`PcapNgWriter`] to write pcapng data and [`PcapNgReaderIterator`] for iteration over owned blocks.

pub mod blocks;
pub mod errors;

pub(crate) mod state;
pub use state::PcapNgState;

pub(crate) mod parser;
pub use parser::PcapNgParser;

pub(crate) mod reader;
pub use reader::{PcapNgReader, PcapNgReaderIterator};

pub(crate) mod writer;
pub use writer::PcapNgWriter;
