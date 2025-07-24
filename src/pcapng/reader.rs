use std::io::Read;

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::{PcapNgParser, PcapNgState};
use crate::errors::PcapError;
use crate::read_buffer::ReadBuffer;


/// Reads a PcapNg from a reader.
///
/// # Example
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block() {
///     //Check if there is no error
///     let block = block.unwrap();
///
///     //Do something
/// }
/// ```
pub struct PcapNgReader<R: Read> {
    parser: PcapNgParser,
    reader: ReadBuffer<R>,
}

impl<R: Read> PcapNgReader<R> {
    /// Creates a new [`PcapNgReader`] from a reader.
    ///
    /// Parses the first block which must be a valid SectionHeaderBlock.
    pub fn new(reader: R) -> Result<PcapNgReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapNgParser::new)?;
        Ok(Self { parser, reader })
    }

    /// Returns the next [`Block`] and the current [`PcapNgState`].
    pub fn next_block_and_state(&mut self) -> Option<Result<(Block, &PcapNgState), PcapError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    // # SAFETY
                    // Block must NOT contain a mutable reference to the state.
                    // Keep the annotations to be sure that only the lifetime is trnasmuted.
                    let res: Result<Block<'_>, PcapError> = self.reader.parse_with(|src| self.parser.next_block(src));
                    let res: Result<Block<'_>, PcapError> = unsafe {std::mem::transmute(res)};

                    let state = &self.parser.state;

                    Some(res.map(|blk| (blk, state)))
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the next [`Block`].
    pub fn next_block(&mut self) -> Option<Result<Block, PcapError>> {
        match self.next_block_and_state() {
            None => None,
            Some(Ok((block, _state))) => Some(Ok(block)),
            Some(Err(e)) => Some(Err(e))
        }
    }

    /// Returns the next [`RawBlock`].
    pub fn next_raw_block(&mut self) -> Option<Result<RawBlock, PcapError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with(|src| self.parser.next_raw_block(src)))
                }
                else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        self.parser.section()
    }

    /// Returns all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        self.parser.interfaces()
    }

    /// Returns the [`InterfaceDescriptionBlock`] corresponding to the given packet
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces().get(packet.interface_id as usize)
    }

    /// Consumes the [`Self`], returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Gets a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        self.reader.get_ref()
    }

    /// Returns the number of bytes parsed so far.
    pub fn bytes_parsed(&self) -> u64 {
        self.reader.bytes_used
    }
}
