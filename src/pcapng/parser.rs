use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use super::PcapNgState;
use super::blocks::block_common::{Block, RawBlock};
use crate::Endianness;
use crate::pcapng::errors::{PcapNgFormatError, PcapNgParseError};

/// Parses a pcapng stream from a byte slice.
///
/// Match [`PcapNgParseError::IncompleteBuffer`] to determine whether more data is needed.
///
/// Some typed conversion errors from [`Self::next_block`] can be recovered by
/// calling [`Self::next_raw_block`] with the same input slice.
///
/// Use [`Self::state`] to access the current section and interfaces.
///
/// # Examples
/// ```rust,no_run
/// use pcap_file::pcapng::errors::PcapNgParseError;
/// use pcap_file::pcapng::PcapNgParser;
///
/// let pcap = std::fs::read("test.pcapng").expect("Error reading file");
/// let mut src = &pcap[..];
///
/// let (rem, mut pcapng_parser) = PcapNgParser::new(src).unwrap();
/// src = rem;
///
/// while !src.is_empty() {
///     match pcapng_parser.next_block(src) {
///         Ok((rem, block)) => {
///             // Process the block.
///
///             // Advance to the remaining input.
///             src = rem;
///         },
///         Err(PcapNgParseError::IncompleteBuffer(_,_)) => {
///             // Load more data into src if parsing a stream.
///         },
///         Err(_) => {
///             // Handle an unrecoverable parsing error.
///         },
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgParser {
    /// Current state of the pcapng format.
    pub(crate) state: PcapNgState,
}

impl PcapNgParser {
    /// Creates a new [`PcapNgParser`].
    ///
    /// Parses the first block, which must be a valid Section Header Block.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapNgParseError::IncompleteBuffer`] if the input does not
    ///   contain a complete first block.
    /// - Returns an error if the input does not start with a valid Section
    ///   Header Block.
    pub fn new(src: &[u8]) -> Result<(&[u8], Self), PcapNgParseError> {
        // Always use BigEndian here because we can't know the SectionHeaderBlock endianness
        let mut state = PcapNgState::default();

        let (rem, raw_block) = RawBlock::from_slice::<BigEndian>(src)?;
        let block = Block::try_from_raw_block::<BigEndian>(&state, raw_block)
            .map_err(|error| PcapNgParseError::BlockConversion(error.into()))?;

        if !matches!(&block, Block::SectionHeader(_)) {
            return Err(PcapNgFormatError::MissingSectionHeader.into());
        };

        state.update_from_block(&block);

        let parser = PcapNgParser { state };

        Ok((rem, parser))
    }

    /// Returns the remainder and the next [`Block`].
    ///
    /// # Errors
    /// - Returns [`PcapNgParseError::IncompleteBuffer`] if the input does not
    ///   contain a complete block. Load more data and retry with the same input.
    /// - Returns another error if the block is malformed. These errors leave
    ///   the input and parser state unchanged. Typed
    ///   conversion errors for non-state blocks can be recovered by calling
    ///   [`Self::next_raw_block`] with the same input slice.
    pub fn next_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapNgParseError> {
        // This function doesn't call `self::next_raw_block()` because converting the Block before updating the state is faster and better for error handling.

        /// Inner function to parse the next Block.
        fn next_block_inner<'a, B: ByteOrder>(
            parser: &mut PcapNgParser,
            src: &'a [u8],
        ) -> Result<(&'a [u8], Block<'a>), PcapNgParseError> {
            let (rem, raw_block) = RawBlock::from_slice::<B>(src)?;
            let state = &parser.state;
            let block = raw_block
                .try_into_block(state)
                .map_err(|error| PcapNgParseError::BlockConversion(error.into()))?;

            parser.state.update_from_block(&block);
            Ok((rem, block))
        }

        // Read next Block
        match self.state.section.endianness {
            Endianness::Big => next_block_inner::<BigEndian>(self, src),
            Endianness::Little => next_block_inner::<LittleEndian>(self, src),
        }
    }

    /// Returns the remainder and the next [`RawBlock`].
    /// This method is more permissive than [`Self::next_block`].
    ///
    /// A [`RawBlock`] can be validated using [`RawBlock::try_into_block`].
    /// Section Header and Interface Description blocks are still decoded before
    /// returning so the parser can keep its state consistent. If decoding one of
    /// those state-changing blocks fails, the error is not recoverable by this
    /// parser and no raw block is returned.
    ///
    /// # Errors
    /// - Returns [`PcapNgParseError::IncompleteBuffer`] if the input does not
    ///   contain a complete block. Load more data and retry with the same input.
    /// - Returns [`PcapNgParseError::StateUpdate`] if a state-changing raw block
    ///   cannot be decoded.
    /// - Returns another error if the raw block is malformed. These errors leave
    ///   the input and parser state unchanged and are not recoverable with this
    ///   parser.
    pub fn next_raw_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapNgParseError> {
        /// Inner function to parse the next RawBlock.
        fn next_raw_block_inner<'a, B: ByteOrder>(
            parser: &mut PcapNgParser,
            src: &'a [u8],
        ) -> Result<(&'a [u8], RawBlock<'a>), PcapNgParseError> {
            let (rem, raw_block) = RawBlock::from_slice::<B>(src)?;

            if let Some(block) = parser.state.decode_block_if_needed(&raw_block)? {
                parser.state.update_from_block(&block);
            }

            Ok((rem, raw_block))
        }

        // Read next RawBlock
        match self.state.section.endianness {
            Endianness::Big => next_raw_block_inner::<BigEndian>(self, src),
            Endianness::Little => next_raw_block_inner::<LittleEndian>(self, src),
        }
    }

    /// Returns the current [`PcapNgState`].
    ///
    /// Use the state to access the current section, interfaces, endianness, and
    /// timestamp conversion methods.
    pub fn state(&self) -> &PcapNgState {
        &self.state
    }
}
