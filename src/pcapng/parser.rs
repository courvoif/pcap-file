/* ----- Imports ----- */

use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use super::PcapNgState;
use super::blocks::block_common::{Block, RawBlock};
use crate::Endianness;
use crate::pcapng::errors::{PcapNgFormatError, PcapNgParseError};

/* ----- Parser ----- */

/// Parses a PcapNg from a slice of bytes.
///
/// You can match on [`PcapNgParseError::IncompleteBuffer`](crate::pcapng::PcapNgParseError) to know if the parser needs more data.
///
/// # Example
/// ```rust,no_run
/// use pcap_file::pcapng::{PcapNgParseError, PcapNgParser};
///
/// let pcap = std::fs::read("test.pcapng").expect("Error reading file");
/// let mut src = &pcap[..];
///
/// let (rem, mut pcapng_parser) = PcapNgParser::new(src, true).unwrap();
/// src = rem;
///
/// while !src.is_empty() {
///     match pcapng_parser.next_block(src) {
///         Ok((rem, block)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///         },
///         Err(PcapNgParseError::IncompleteBuffer(_,_)) => {
///             // Load more data into src if parsing a stream.
///         },
///         Err(_) => {
///             // Handle parsing error
///         },
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgParser {
    /// Current state of the pcapng format.
    pub(crate) state: PcapNgState,
    strict: bool,
}

impl PcapNgParser {
    /// Creates a parser and decodes the initial Section Header Block.
    ///
    /// When `strict` is true, typed blocks are semantically validated after
    /// decoding. Raw operations leave semantic validation to the caller.
    /// Framing, bounds, and required conversions are checked in either mode.
    pub fn new(src: &[u8], strict: bool) -> Result<(&[u8], Self), PcapNgParseError> {
        // Always use BigEndian here because we can't know the SectionHeaderBlock endianness
        let mut state = PcapNgState::default();

        let (rem, raw_block) = RawBlock::from_slice::<BigEndian>(src)?;
        let block = Block::try_from_raw_block::<BigEndian>(&state, &raw_block)?;

        if !matches!(&block, Block::SectionHeader(_)) {
            return Err(PcapNgFormatError::MissingSectionHeader.into());
        };

        block
            .validate(&state)
            .map_err(|source| block.conversion_error(source))?;

        state.update_from_block(&block);

        let parser = PcapNgParser { state, strict };

        Ok((rem, parser))
    }

    /// Returns the remainder and the next typed block, validating it in strict mode.
    ///
    /// # Errors
    /// - Only [`PcapNgParseError::IncompleteBuffer`] is recoverable (by loading more data).
    /// - Other errors will prevent the parser from advancing further.
    ///   Some of these can be recovered by calling [`Self::next_raw_block`].
    pub fn next_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapNgParseError> {
        // This function doesn't call `self::next_raw_block()` because converting the Block before updating the state is faster and better for error handling.

        // Read next Block
        return match self.state.section.endianness {
            Endianness::Big => next_block_inner::<BigEndian>(self, src),
            Endianness::Little => next_block_inner::<LittleEndian>(self, src),
        };

        /// Inner function to parse the next Block.
        fn next_block_inner<'a, B: ByteOrder>(
            parser: &mut PcapNgParser,
            src: &'a [u8],
        ) -> Result<(&'a [u8], Block<'a>), PcapNgParseError> {
            let (rem, raw_block) = RawBlock::from_slice::<B>(src)?;
            let state = &parser.state;
            let block = raw_block.try_into_block(state)?;

            if parser.strict {
                block.validate(state).map_err(|source| block.conversion_error(source))?;
            }

            parser.state.update_from_block(&block);
            Ok((rem, block))
        }
    }

    /// Returns the remainder and the next [`RawBlock`].
    /// More permissive than [`Self::next_block`].
    ///
    /// Strict mode does not apply to raw block contents. Decode with
    /// [`RawBlock::try_into_block`] and call [`Block::validate`] explicitly
    /// when semantic validation is wanted.
    /// Section Header and Interface Description blocks are still decoded before
    /// returning so the parser can keep its state consistent. If decoding one of
    /// those state-changing blocks fails, the error is not recoverable by this
    /// parser and no raw block is returned.
    ///
    /// # Errors
    /// - Only [`PcapNgParseError::IncompleteBuffer`] is recoverable (by loading more data).
    /// - [`PcapNgParseError::StateUpdate`] can happen when a state-changing raw block cannot be decoded.
    /// - All other errors will prevent the parser from advancing further.
    pub fn next_raw_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapNgParseError> {
        // Read next RawBlock
        return match self.state.section.endianness {
            Endianness::Big => next_raw_block_inner::<BigEndian>(self, src),
            Endianness::Little => next_raw_block_inner::<LittleEndian>(self, src),
        };

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
    }

    /// Returns whether typed blocks are semantically validated.
    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Returns the current [`PcapNgState`].
    pub fn state(&self) -> &PcapNgState {
        &self.state
    }
}
