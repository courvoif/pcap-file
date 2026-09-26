/* ----- Imports ----- */

use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use super::PcapNgState;
use super::blocks::block_common::{Block, RawBlock};
use crate::Endianness;
use crate::pcapng::StateUpdateError;
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
    /// Creates a parser from the initial Section Header Block and returns the
    /// remaining input.
    /// The input must start with a valid Section Header Block.
    ///
    /// Set `strict` to `true` to reject when reading them with
    /// [`Self::next_block`].
    /// Set it to `false` to validate those blocks yourself.
    /// Section Header and Interface Description blocks must be valid in either
    /// mode.
    ///
    /// # Errors
    /// - On [`PcapNgParseError::IncompleteBuffer`], provide the rest of the
    ///   initial Section Header Block and call this method again.
    /// - If the initial block is invalid or is not a Section Header Block,
    ///   provide a valid pcapng capture.
    pub fn new(src: &[u8], strict: bool) -> Result<(&[u8], Self), PcapNgParseError> {
        // Always use BigEndian here because we can't know the SectionHeaderBlock endianness
        let mut state = PcapNgState::default();

        let (rem, raw_block) = RawBlock::from_slice::<BigEndian>(src)?;

        let block = Block::try_from_raw_block::<BigEndian>(&state, &raw_block)?;

        if !matches!(&block, Block::SectionHeader(_)) {
            return Err(PcapNgFormatError::MissingSectionHeader.into());
        }

        block.validate(&state).map_err(StateUpdateError::from)?;
        state.update_from_block(&block);

        let parser = PcapNgParser { state, strict };

        Ok((rem, parser))
    }

    /// Returns the remaining input and the next typed [`Block`].
    ///
    /// Use [`Self::state`] to inspect the current section and interface state.
    ///
    /// The `strict` setting from [`Self::new`] controls semantic validation of
    /// blocks other than Section Header and Interface Description blocks.
    ///
    /// # Errors
    /// - On [`PcapNgParseError::IncompleteBuffer`], provide more bytes and retry
    ///   with the same input.
    /// - On [`PcapNgParseError::Block`] for other block types, call
    ///   [`Self::next_raw_block`] with the same input.
    /// - On an invalid format or state error, stop or correct the input before
    ///   continuing.
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

            // State-changing blocks must be handled separately to keep the parser state valid.
            // Failures during their state preparation must be returned as fatal state-update errors.
            let block = if let Some(block) = parser.state.decode_block_if_needed(&raw_block)? {
                block.validate(&parser.state).map_err(StateUpdateError::from)?;
                parser.state.update_from_block(&block);
                block
            } else {
                let block = raw_block.try_into_block(&parser.state)?;
                if parser.strict {
                    block.validate(&parser.state)?;
                }
                block
            };

            Ok((rem, block))
        }
    }

    /// Returns the remaining input and the next [`RawBlock`].
    /// Use this when you need a block's raw form.
    ///
    /// Use the current state with [`RawBlock::try_into_block`] to decode the
    /// block, then with [`Block::validate`] to check it semantically.
    ///
    /// The `strict` setting does not affect this method.
    /// Section Header and Interface Description blocks must be valid in either
    /// mode.
    ///
    /// # Errors
    /// - On [`PcapNgParseError::IncompleteBuffer`], provide more bytes and retry
    ///   with the same input.
    /// - On an invalid format or state error, stop or correct the input before
    ///   continuing.
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
                block.validate(&parser.state).map_err(StateUpdateError::from)?;
                parser.state.update_from_block(&block);
            }

            Ok((rem, raw_block))
        }
    }

    /// Returns whether blocks other than Section Header and Interface
    /// Description blocks are semantically validated.
    ///
    /// Section Header and Interface Description blocks are always validated.
    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Returns the current [`PcapNgState`].
    pub fn state(&self) -> &PcapNgState {
        &self.state
    }
}
