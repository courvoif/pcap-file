use std::io::Read;

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::{PcapNgParser, PcapNgState};
use crate::pcapng::errors::PcapNgReadError;
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
///     let (block, state) = block.unwrap();
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
    pub fn new(reader: R) -> Result<PcapNgReader<R>, PcapNgReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapNgParser::new)?;
        Ok(Self { parser, reader })
    }

    /// Returns the next [`Block`] and the current [`PcapNgState`].
    /// [`None`] means that the reader have reached the EoF.
    /// Won't advance the reader past any malformed packets.
    ///
    /// # Errors
    /// - Only some variants of [`PcapNgReadError::Io`] are directly recoverable.
    /// - [`PcapNgReadError::BlockConversion`] can be recovered by calling [`Self::next_raw_block`].
    /// - Other errors will prevent the reader from advancing further.
    #[must_use = "Not checking the result can lead to an infinite loop because the reader may not advance on error"]
    pub fn next_block<'a>(&'a mut self) -> Option<Result<(Block<'a>, &'a PcapNgState), PcapNgReadError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    // # SAFETY
                    // Block must NOT contain a mutable reference to the state.
                    // Keep the annotations to be sure that only the lifetime is trnasmuted.
                    let res: Result<Block<'_>, PcapNgReadError> = self.reader.parse_with(|src| self.parser.next_block(src));
                    let res: Result<Block<'_>, PcapNgReadError> = unsafe { std::mem::transmute(res) };

                    let state = &self.parser.state;

                    Some(res.map(|blk| (blk, state)))
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapNgReadError::Io(e))),
        }
    }

    /// Returns the next [`RawBlock`] and the current [`PcapNgState`].
    /// [`None`] means that the reader have reached the EoF.
    /// More permissive than [`Self::next_block`].
    ///
    /// A [`RawBlock`] can be validated using [`RawBlock::try_into_block`].
    ///
    /// # Errors
    /// - Only some variants of [`PcapNgReadError::Io`] are directly recoverable.
    /// - All other errors will prevent the reader from advancing further.
    #[must_use = "Not checking the result can lead to an infinite loop because the reader may not advance on error"]
    pub fn next_raw_block<'a>(&'a mut self) -> Option<Result<(RawBlock<'a>, &'a PcapNgState), PcapNgReadError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    // # SAFETY
                    // Block must NOT contain a mutable reference to the state.
                    // Keep the annotations to be sure that only the lifetime is transmuted.
                    let res: Result<RawBlock<'_>, PcapNgReadError> = self.reader.parse_with(|src| self.parser.next_raw_block(src));
                    let res: Result<RawBlock<'_>, PcapNgReadError> = unsafe { std::mem::transmute(res) };

                    let state = &self.parser.state;

                    Some(res.map(|blk| (blk, state)))
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapNgReadError::Io(e))),
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
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock<'_>> {
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
