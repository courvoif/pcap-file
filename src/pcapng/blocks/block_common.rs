//! Common block types.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};
use derive_into_owned::IntoOwned;

use super::custom::CustomBlock;
use super::enhanced_packet::EnhancedPacketBlock;
use super::interface_description::InterfaceDescriptionBlock;
use super::interface_statistics::InterfaceStatisticsBlock;
use super::name_resolution::NameResolutionBlock;
use super::packet::PacketBlock;
use super::section_header::SectionHeaderBlock;
use super::simple_packet::SimplePacketBlock;
use super::systemd_journal_export::SystemdJournalExportBlock;
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{
    BlockError, BlockValidationError, PcapNgFormatError, PcapNgWriteError, RawBlockParseError, WriteError,
};

/* ----- Raw blocks ----- */

//   0               1               2               3
//   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                          Block Type                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Block Total Length                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  /                          Block Body                           /
//  /          /* variable length, aligned to 32 bits */            /
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Block Total Length                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// PcapNg Block
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct RawBlock<'a> {
    /// Type field
    pub type_: u32,
    /// Initial length field
    pub initial_len: u32,
    /// Body of the block
    pub body: Cow<'a, [u8]>,
    /// Trailer length field
    pub trailer_len: u32,
}

impl<'a> RawBlock<'a> {
    /// Parses a borrowed [`RawBlock`] from a slice.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), RawBlockParseError> {
        if slice.len() < 12 {
            return Err(RawBlockParseError::IncompleteBuffer(12, slice.len()));
        }

        let type_ = slice.read_u32::<B>().expect("slice length checked above");

        // Special case for the section header because we don't know the endianness yet
        if type_ == SectionHeaderBlock::TYPE {
            let initial_len = slice.read_u32::<BigEndian>().expect("slice length checked above");

            // Check the first field of the Section header to find the endianness
            let mut tmp_slice = slice;
            let magic = tmp_slice.read_u32::<BigEndian>().expect("slice length checked above");
            let res = match magic {
                0x1A2B3C4D => inner_parse::<BigEndian>(slice, type_, initial_len),
                0x4D3C2B1A => inner_parse::<LittleEndian>(slice, type_, initial_len.swap_bytes()),
                _ => Err(PcapNgFormatError::InvalidMagicNumber(magic).into()),
            };

            return res;
        } else {
            let initial_len = slice.read_u32::<B>().expect("slice length checked above");
            return inner_parse::<B>(slice, type_, initial_len);
        };

        // Section Header parsing
        fn inner_parse<B: ByteOrder>(
            slice: &[u8],
            type_: u32,
            initial_len: u32,
        ) -> Result<(&[u8], RawBlock<'_>), RawBlockParseError> {
            if initial_len < 12 {
                return Err(PcapNgFormatError::BlockTooShort(12, initial_len as usize).into());
            }

            // Check if there is enough data in the slice for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(RawBlockParseError::IncompleteBuffer(
                    initial_len as usize - 8,
                    slice.len(),
                ));
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize..];

            let trailer_len = rem.read_u32::<B>().expect("slice length checked above");

            let block = RawBlock {
                type_,
                initial_len,
                body: Cow::Borrowed(body),
                trailer_len,
            };

            block.validate()?;

            Ok((rem, block))
        }
    }

    /// Writes a [`RawBlock`] to a writer.
    ///
    /// Uses the endianness of the header.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        self.validate()?;

        writer.write_u32::<B>(self.type_)?;
        writer.write_u32::<B>(self.initial_len)?;
        writer.write_all(&self.body[..])?;
        writer.write_u32::<B>(self.trailer_len)?;

        Ok(self.body.len() + 12)
    }

    /// Validates that the raw block length fields match its body.
    pub fn validate(&self) -> Result<(), PcapNgFormatError> {
        if self.initial_len != self.trailer_len {
            return Err(PcapNgFormatError::BlockLengthMismatch(
                self.initial_len,
                self.trailer_len,
            ));
        }

        if !self.initial_len.is_multiple_of(4) {
            return Err(PcapNgFormatError::BlockNotAligned(self.initial_len as usize));
        }

        if self.initial_len < 12 {
            return Err(PcapNgFormatError::BlockTooShort(12, self.initial_len as usize));
        }

        let expected_len = self.body.len() + 12;
        if self.initial_len as usize != expected_len {
            return Err(PcapNgFormatError::InvalidBlockLength {
                expected: expected_len,
                actual: self.initial_len,
            });
        }

        Ok(())
    }

    /// Decodes a raw block after checking framing, without semantic validation.
    /// Call [`Block::validate`] explicitly to validate the decoded content.
    /// The byteorder is defined by the `state`.
    pub fn try_into_block(&self, state: &PcapNgState) -> Result<Block<'a>, BlockError> {
        match state.section.endianness {
            crate::Endianness::Big => Block::try_from_raw_block::<BigEndian>(state, self),
            crate::Endianness::Little => Block::try_from_raw_block::<LittleEndian>(state, self),
        }
    }

    /// Decodes a raw block after checking framing, without semantic validation.
    /// Call [`Block::validate`] explicitly to validate the decoded content.
    /// The byteorder is defined by the caller.
    pub fn try_into_block_with_byteorder<B: ByteOrder>(&self, state: &PcapNgState) -> Result<Block<'a>, BlockError> {
        Block::try_from_raw_block::<B>(state, self)
    }
}

/* ----- Parsed blocks ----- */

/// A typed PcapNg block.
///
/// Match variants directly to access their typed contents:
///
/// ```rust
/// use pcap_file::pcapng::Block;
///
/// fn inspect(block: &Block<'_>) {
///     if let Block::EnhancedPacket(packet) = block {
///         println!("captured {} bytes", packet.data.len());
///     }
/// }
/// ```
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Block<'a> {
    /// Section Header block
    SectionHeader(SectionHeaderBlock<'a>),
    /// Interface Description block
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    /// Packet block
    Packet(PacketBlock<'a>),
    /// Simple packet block
    SimplePacket(SimplePacketBlock<'a>),
    /// Name Resolution block
    NameResolution(NameResolutionBlock<'a>),
    /// Interface statistics block
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    /// Enhanced packet block
    EnhancedPacket(EnhancedPacketBlock<'a>),
    /// Systemd Journal Export block
    SystemdJournalExport(SystemdJournalExportBlock<'a>),
    /// Custom block, copiable
    CustomCopiable(CustomBlock<'a, true>),
    /// Custom block, non-copiable
    CustomNonCopiable(CustomBlock<'a, false>),
}

impl<'a> Block<'a> {
    /// Tries to create a [`Block`] from a [`RawBlock`], given a [`PcapNgState`].
    ///
    /// If `raw_block` borrows its body, the returned [`Block`] will borrow from
    /// that same buffer whenever possible.
    ///
    /// If `raw_block` owns its body, the block content is parsed and then
    /// converted into an owned [`Block`] before being returned.
    /// Framing is checked, but semantic validation is left to [`Self::validate`].
    pub fn try_from_raw_block<B: ByteOrder>(
        state: &PcapNgState,
        raw_block: &RawBlock<'a>,
    ) -> Result<Block<'a>, BlockError> {
        let type_ = raw_block.type_;

        return match &raw_block.body {
            Cow::Borrowed(body) => parse_body::<B>(state, type_, body),
            Cow::Owned(body) => parse_body::<B>(state, type_, body).map(|block| block.into_owned()),
        };

        fn parse_body<'a, B: ByteOrder>(
            state: &PcapNgState,
            type_: u32,
            body: &'a [u8],
        ) -> Result<Block<'a>, BlockError> {
            match type_ {
                SectionHeaderBlock::TYPE => {
                    SectionHeaderBlock::from_body::<B>(state, body).map(|(_, blk)| Block::SectionHeader(blk))
                }
                InterfaceDescriptionBlock::TYPE => InterfaceDescriptionBlock::from_body::<B>(state, body)
                    .map(|(_, blk)| Block::InterfaceDescription(blk)),
                PacketBlock::TYPE => PacketBlock::from_body::<B>(state, body).map(|(_, blk)| Block::Packet(blk)),
                SimplePacketBlock::TYPE => {
                    SimplePacketBlock::from_body::<B>(state, body).map(|(_, blk)| Block::SimplePacket(blk))
                }
                NameResolutionBlock::TYPE => {
                    NameResolutionBlock::from_body::<B>(state, body).map(|(_, blk)| Block::NameResolution(blk))
                }
                InterfaceStatisticsBlock::TYPE => InterfaceStatisticsBlock::from_body::<B>(state, body)
                    .map(|(_, blk)| Block::InterfaceStatistics(blk)),
                EnhancedPacketBlock::TYPE => {
                    EnhancedPacketBlock::from_body::<B>(state, body).map(|(_, blk)| Block::EnhancedPacket(blk))
                }
                SystemdJournalExportBlock::TYPE => SystemdJournalExportBlock::from_body::<B>(state, body)
                    .map(|(_, blk)| Block::SystemdJournalExport(blk)),
                CustomBlock::<true>::TYPE => {
                    CustomBlock::from_body::<B>(state, body).map(|(_, blk)| Block::CustomCopiable(blk))
                }
                CustomBlock::<false>::TYPE => {
                    CustomBlock::from_body::<B>(state, body).map(|(_, blk)| Block::CustomNonCopiable(blk))
                }
                _ => Err(BlockValidationError::UnknownType),
            }
            .map_err(|source| BlockError {
                type_,
                source: source.into(),
            })
        }
    }

    /// Encodes a framed block without semantic validation.
    /// Call [`Self::validate`] explicitly, or use a strict [`crate::pcapng::PcapNgWriter`].
    /// Encoding conversions and size limits are checked in either case.
    pub fn write_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockError>> {
        let result = match self {
            Self::SectionHeader(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::InterfaceDescription(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::Packet(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::SimplePacket(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::NameResolution(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::InterfaceStatistics(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::EnhancedPacket(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::SystemdJournalExport(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::CustomCopiable(b) => inner_write_to::<B, _, W>(state, b, writer),
            Self::CustomNonCopiable(b) => inner_write_to::<B, _, W>(state, b, writer),
        };

        return result.map_err(|error| match error {
            WriteError::Io(error) => WriteError::Io(error),
            WriteError::Other(source) => WriteError::Other(BlockError {
                type_: self.type_code(),
                source: Box::new(source),
            }),
        });

        fn inner_write_to<'block, B: ByteOrder, BL: PcapNgBlock<'block>, W: Write>(
            state: &PcapNgState,
            block: &BL,
            writer: &mut W,
        ) -> Result<usize, WriteError<BlockValidationError>> {
            // Fake write to compute the data length
            // Required encoding conversions fail before the destination is written.
            let data_len = block.write_body_to::<B, _>(state, &mut std::io::sink())?;
            let pad_len = (4 - (data_len % 4)) % 4;

            // Block length calculation
            let block_len = data_len + pad_len + 12;

            // Check that there wasn't an overflow
            if block_len < data_len {
                return Err(WriteError::Other(BlockValidationError::BlockTooLarge {
                    actual: data_len as u64,
                    maximum: u32::MAX as u64,
                }));
            }

            // Check that the block length fits within the u32 limit
            let block_len: u32 = block_len.try_into().map_err(|_| {
                WriteError::Other(BlockValidationError::BlockTooLarge {
                    actual: block_len as u64,
                    maximum: u32::MAX as u64,
                })
            })?;

            writer.write_u32::<B>(BL::TYPE)?;
            writer.write_u32::<B>(block_len)?;
            block.write_body_to::<B, _>(state, writer)?;
            writer.write_all(&[0_u8; 3][..pad_len])?;
            writer.write_u32::<B>(block_len)?;

            Ok(block_len as usize)
        }
    }

    /// Validates the block's semantic constraints against the current state.
    pub fn validate(&self, state: &PcapNgState) -> Result<(), BlockError> {
        match self {
            Self::SectionHeader(block) => block.validate(state),
            Self::InterfaceDescription(block) => block.validate(state),
            Self::Packet(block) => block.validate(state),
            Self::SimplePacket(block) => block.validate(state),
            Self::NameResolution(block) => block.validate(state),
            Self::InterfaceStatistics(block) => block.validate(state),
            Self::EnhancedPacket(block) => block.validate(state),
            Self::SystemdJournalExport(block) => block.validate(state),
            Self::CustomCopiable(block) => block.validate(state),
            Self::CustomNonCopiable(block) => block.validate(state),
        }
        .map_err(|source| BlockError {
            type_: self.type_code(),
            source: source.into(),
        })
    }

    /// Converts this block into a packet view using the current interface state.
    ///
    /// See [`crate::pcapng::PcapNgPacket::from_block`] for ownership and errors.
    pub fn into_pcapng_packet(
        self,
        state: &PcapNgState,
    ) -> Result<crate::pcapng::PcapNgPacket<'a>, crate::pcapng::errors::PacketConversionError<'a>> {
        crate::pcapng::PcapNgPacket::from_block(self, state)
    }

    /// Returns the numeric block type.
    pub fn type_code(&self) -> u32 {
        match self {
            Self::SectionHeader(_) => <SectionHeaderBlock as PcapNgBlock>::TYPE,
            Self::InterfaceDescription(_) => <InterfaceDescriptionBlock as PcapNgBlock>::TYPE,
            Self::Packet(_) => <PacketBlock as PcapNgBlock>::TYPE,
            Self::SimplePacket(_) => <SimplePacketBlock as PcapNgBlock>::TYPE,
            Self::NameResolution(_) => <NameResolutionBlock as PcapNgBlock>::TYPE,
            Self::InterfaceStatistics(_) => <InterfaceStatisticsBlock as PcapNgBlock>::TYPE,
            Self::EnhancedPacket(_) => <EnhancedPacketBlock as PcapNgBlock>::TYPE,
            Self::SystemdJournalExport(_) => <SystemdJournalExportBlock as PcapNgBlock>::TYPE,
            Self::CustomCopiable(_) => <CustomBlock<'a, true> as PcapNgBlock>::TYPE,
            Self::CustomNonCopiable(_) => <CustomBlock<'a, false> as PcapNgBlock>::TYPE,
        }
    }
}

/* ----- Common block interface ----- */

/// Common interface for the PcapNg blocks
pub trait PcapNgBlock<'a> {
    /// Numeric block type stored in the frame.
    const TYPE: u32;
    /// Human-readable block name.
    const NAME: &'static str;

    /// Explicitly validates semantic constraints.
    /// Low-level decoding and encoding
    /// do not call this method; strict parsers and writers do.
    fn validate(&self, _state: &PcapNgState) -> Result<(), BlockValidationError> {
        Ok(())
    }

    /// Decodes a block body using the supplied state, without semantic validation.
    /// Required bounds and representation checks still apply.
    fn from_body<B: ByteOrder>(state: &PcapNgState, slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockValidationError>
    where
        Self: std::marker::Sized;

    /// Encodes a block body without semantic validation.
    /// Required conversions return errors even if [`Self::validate`] was not called.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>>;

    /// Convert a block into the [`Block`] enumeration
    fn into_block(self) -> Block<'a>;
}

/* ----- Block names ----- */

/// Convert a block type into its name
pub fn block_name(type_: u32) -> &'static str {
    match type_ {
        SectionHeaderBlock::TYPE => SectionHeaderBlock::NAME,
        InterfaceDescriptionBlock::TYPE => InterfaceDescriptionBlock::NAME,
        PacketBlock::TYPE => PacketBlock::NAME,
        SimplePacketBlock::TYPE => SimplePacketBlock::NAME,
        NameResolutionBlock::TYPE => NameResolutionBlock::NAME,
        InterfaceStatisticsBlock::TYPE => InterfaceStatisticsBlock::NAME,
        EnhancedPacketBlock::TYPE => EnhancedPacketBlock::NAME,
        SystemdJournalExportBlock::TYPE => SystemdJournalExportBlock::NAME,
        CustomBlock::<true>::TYPE => CustomBlock::<true>::NAME,
        CustomBlock::<false>::TYPE => CustomBlock::<false>::NAME,
        _ => "Unknown Block",
    }
}

/* ----- Tests ----- */

#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use std::borrow::Cow;

    use byteorder_slice::BigEndian;

    use super::*;
    use crate::Endianness;
    use crate::pcapng::PcapNgState;
    use crate::pcapng::errors::PcapNgFormatError;

    /* ----- Block metadata ----- */

    #[test]
    fn block_type_codes_and_names_match_wire_format() {
        let blocks = [
            (SectionHeaderBlock::TYPE, SectionHeaderBlock::NAME, 0x0A0D0D0A),
            (
                InterfaceDescriptionBlock::TYPE,
                InterfaceDescriptionBlock::NAME,
                0x00000001,
            ),
            (PacketBlock::TYPE, PacketBlock::NAME, 0x00000002),
            (SimplePacketBlock::TYPE, SimplePacketBlock::NAME, 0x00000003),
            (NameResolutionBlock::TYPE, NameResolutionBlock::NAME, 0x00000004),
            (
                InterfaceStatisticsBlock::TYPE,
                InterfaceStatisticsBlock::NAME,
                0x00000005,
            ),
            (EnhancedPacketBlock::TYPE, EnhancedPacketBlock::NAME, 0x00000006),
            (
                SystemdJournalExportBlock::TYPE,
                SystemdJournalExportBlock::NAME,
                0x00000009,
            ),
            (CustomBlock::<true>::TYPE, CustomBlock::<true>::NAME, 0x00000BAD),
            (CustomBlock::<false>::TYPE, CustomBlock::<false>::NAME, 0x40000BAD),
        ];
        for (type_code, name, expected) in blocks {
            assert_eq!(type_code, expected);
            assert_eq!(block_name(type_code), name);
        }
        assert_eq!(block_name(u32::MAX), "Unknown Block");
    }

    /* ----- Raw block conversion and validation ----- */

    #[test]
    fn try_from_raw_block_accepts_owned_bodies() {
        let raw_block = RawBlock {
            type_: SectionHeaderBlock::TYPE,
            initial_len: 28,
            body: Cow::Owned(vec![
                0x1A, 0x2B, 0x3C, 0x4D, // byte-order magic
                0x00, 0x01, // major version
                0x00, 0x00, // minor version
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // section length
            ]),
            trailer_len: 28,
        };

        let block = Block::try_from_raw_block::<BigEndian>(&PcapNgState::default(), &raw_block).unwrap();

        match block {
            Block::SectionHeader(block) => {
                assert_eq!(block.endianness, Endianness::Big);
                assert_eq!(block.major_version, 1);
                assert_eq!(block.minor_version, 0);
                assert!(block.options.is_empty());
            }
            other => panic!("expected SectionHeader block, got {other:?}"),
        }
    }

    #[test]
    fn raw_block_validation_rejects_body_length_mismatch() {
        let raw_block = RawBlock {
            type_: SectionHeaderBlock::TYPE,
            initial_len: 32,
            body: Cow::Owned(vec![0; 16]),
            trailer_len: 32,
        };

        let err = raw_block.validate().unwrap_err();

        assert!(matches!(
            err,
            PcapNgFormatError::InvalidBlockLength {
                expected: 28,
                actual: 32,
            }
        ));
    }
}
