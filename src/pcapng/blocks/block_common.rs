//! Common block types.

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
use super::unknown::UnknownBlock;
use crate::pcapng::{ContentValidationError, PcapNgState};
use crate::pcapng::errors::{BlockContentParseError, BlockConversionError, PcapNgFormatError, PcapNgWriteError, RawBlockParseError};

/// Section header block type
pub const SECTION_HEADER_BLOCK: u32 = 0x0A0D0D0A;
/// Interface description block type
pub const INTERFACE_DESCRIPTION_BLOCK: u32 = 0x00000001;
/// Packet block type
pub const PACKET_BLOCK: u32 = 0x00000002;
/// Simple packet block type
pub const SIMPLE_PACKET_BLOCK: u32 = 0x00000003;
/// Name resolution block type
pub const NAME_RESOLUTION_BLOCK: u32 = 0x00000004;
/// Interface statistic block type
pub const INTERFACE_STATISTIC_BLOCK: u32 = 0x00000005;
/// Enhanced packet block type
pub const ENHANCED_PACKET_BLOCK: u32 = 0x00000006;
/// Systemd journal export block type
pub const SYSTEMD_JOURNAL_EXPORT_BLOCK: u32 = 0x00000009;
/// Custom block type, copiable
pub const CUSTOM_BLOCK_COPIABLE: u32 = 0x00000BAD;
/// Custom block type, non-copiable
pub const CUSTOM_BLOCK_NON_COPIABLE: u32 = 0x40000BAD;

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
#[derive(Clone, Debug)]
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
        if type_ == SECTION_HEADER_BLOCK {
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
        fn inner_parse<B: ByteOrder>(slice: &[u8], type_: u32, initial_len: u32) -> Result<(&[u8], RawBlock<'_>), RawBlockParseError> {
            if !initial_len.is_multiple_of(4) {
                return Err(PcapNgFormatError::BlockNotAligned(initial_len as usize).into());
            }

            if initial_len < 12 {
                return Err(PcapNgFormatError::BlockTooShort(12, initial_len as usize).into());
            }

            // Check if there is enough data in the slice for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(RawBlockParseError::IncompleteBuffer(initial_len as usize - 8, slice.len() + 8));
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize..];

            let trailer_len = rem.read_u32::<B>().expect("slice length checked above");

            if initial_len != trailer_len {
                return Err(PcapNgFormatError::BlockLengthMismatch(initial_len, trailer_len).into());
            }

            let block = RawBlock { type_, initial_len, body: Cow::Borrowed(body), trailer_len };

            Ok((rem, block))
        }
    }

    /// Writes a [`RawBlock`] to a writer.
    ///
    /// Uses the endianness of the header.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        writer.write_u32::<B>(self.type_)?;
        writer.write_u32::<B>(self.initial_len)?;
        writer.write_all(&self.body[..])?;
        writer.write_u32::<B>(self.trailer_len)?;

        Ok(self.body.len() + 12)
    }

    /// Tries to convert a [`RawBlock`] into a [`Block`], using a [`PcapNgState`].
    /// The byteorder is defined by the `state`.
    pub fn try_into_block(self, state: &PcapNgState) -> Result<Block<'a>, BlockConversionError> {
        match state.section.endianness {
            crate::Endianness::Big => Block::try_from_raw_block::<BigEndian>(state, self),
            crate::Endianness::Little => Block::try_from_raw_block::<LittleEndian>(state, self),
        }
    }

    /// Tries to convert a [`RawBlock`] into a [`Block`], using a [`PcapNgState`].
    /// The byteorder is defined by the caller
    pub fn try_into_block_with_byteorder<B: ByteOrder>(self, state: &PcapNgState) -> Result<Block<'a>, BlockConversionError> {
        Block::try_from_raw_block::<B>(state, self)
    }
}

/// PcapNg parsed blocks
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
    /// Unknown block
    Unknown(UnknownBlock<'a>),
}

impl<'a> Block<'a> {
    /// Tries to create a [`Block`] from a [`RawBlock`], given a [`PcapNgState`].
    ///
    /// If `raw_block` borrows its body, the returned [`Block`] will borrow from
    /// that same buffer whenever possible.
    ///
    /// If `raw_block` owns its body, the block content is parsed and then
    /// converted into an owned [`Block`] before being returned.
    pub fn try_from_raw_block<B: ByteOrder>(state: &PcapNgState, raw_block: RawBlock<'a>) -> Result<Block<'a>, BlockConversionError> {
        fn parse_body<'a, B: ByteOrder>(
            state: &PcapNgState,
            type_: u32,
            initial_len: u32,
            body: &'a [u8],
        ) -> Result<Block<'a>, BlockConversionError> {
            match type_ {
                SECTION_HEADER_BLOCK => SectionHeaderBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::SectionHeader(blk)),
                INTERFACE_DESCRIPTION_BLOCK => {
                    InterfaceDescriptionBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::InterfaceDescription(blk))
                },
                PACKET_BLOCK => PacketBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::Packet(blk)),
                SIMPLE_PACKET_BLOCK => SimplePacketBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::SimplePacket(blk)),
                NAME_RESOLUTION_BLOCK => NameResolutionBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::NameResolution(blk)),
                INTERFACE_STATISTIC_BLOCK => {
                    InterfaceStatisticsBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::InterfaceStatistics(blk))
                },
                ENHANCED_PACKET_BLOCK => EnhancedPacketBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::EnhancedPacket(blk)),
                SYSTEMD_JOURNAL_EXPORT_BLOCK => {
                    SystemdJournalExportBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::SystemdJournalExport(blk))
                },
                CUSTOM_BLOCK_COPIABLE => CustomBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::CustomCopiable(blk)),
                CUSTOM_BLOCK_NON_COPIABLE => CustomBlock::from_slice::<B>(state, body).map(|(_, blk)| Block::CustomNonCopiable(blk)),
                _ => Ok(Block::Unknown(UnknownBlock::new(type_, initial_len, body))),
            }
            .map_err(|source| BlockConversionError { name: block_name(type_), type_, source })
        }

        let type_ = raw_block.type_;
        let initial_len = raw_block.initial_len;

        match raw_block.body {
            Cow::Borrowed(body) => parse_body::<B>(state, type_, initial_len, body),
            Cow::Owned(body) => parse_body::<B>(state, type_, initial_len, &body).map(|block| block.into_owned()),
        }
    }

    /// Writes a [`Block`] to a writer, using a [`PcapNgState`].
    pub fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        return match self {
            Self::SectionHeader(b) => inner_write_to::<B, _, W>(state, b, SECTION_HEADER_BLOCK, writer),
            Self::InterfaceDescription(b) => inner_write_to::<B, _, W>(state, b, INTERFACE_DESCRIPTION_BLOCK, writer),
            Self::Packet(b) => inner_write_to::<B, _, W>(state, b, PACKET_BLOCK, writer),
            Self::SimplePacket(b) => inner_write_to::<B, _, W>(state, b, SIMPLE_PACKET_BLOCK, writer),
            Self::NameResolution(b) => inner_write_to::<B, _, W>(state, b, NAME_RESOLUTION_BLOCK, writer),
            Self::InterfaceStatistics(b) => inner_write_to::<B, _, W>(state, b, INTERFACE_STATISTIC_BLOCK, writer),
            Self::EnhancedPacket(b) => inner_write_to::<B, _, W>(state, b, ENHANCED_PACKET_BLOCK, writer),
            Self::SystemdJournalExport(b) => inner_write_to::<B, _, W>(state, b, SYSTEMD_JOURNAL_EXPORT_BLOCK, writer),
            Self::CustomCopiable(b) => inner_write_to::<B, _, W>(state, b, CUSTOM_BLOCK_COPIABLE, writer),
            Self::CustomNonCopiable(b) => inner_write_to::<B, _, W>(state, b, CUSTOM_BLOCK_NON_COPIABLE, writer),
            Self::Unknown(b) => inner_write_to::<B, _, W>(state, b, b.type_, writer),
        };

        /// Writes a block to the writer, including its header and padding.
        fn inner_write_to<'a, B: ByteOrder, BL: PcapNgBlock<'a>, W: Write>(
            state: &PcapNgState,
            block: &BL,
            block_code: u32,
            writer: &mut W,
        ) -> Result<usize, PcapNgWriteError> {
            // Fake write to compute the data length
            let data_len = block.write_to::<B, _>(state, &mut std::io::sink())?;
            let pad_len = (4 - (data_len % 4)) % 4;

            // Block length calculation
            let block_len = data_len + pad_len + 12;

            // Check that there wasn't an overflow
            if block_len < data_len {
                return Err(PcapNgWriteError::Validation { field: "block_length", source: ContentValidationError::BlockContentTooBig(data_len as u64) });
            }

            // Check that the block length fits within the u32 limit
            let block_len: u32 = block_len.try_into().map_err(|_| {
                PcapNgWriteError::Validation { field: "block_length", source: ContentValidationError::BlockContentTooBig(block_len as u64) }
            })?;

            writer.write_u32::<B>(block_code)?;
            writer.write_u32::<B>(block_len)?;
            block.write_to::<B, _>(state, writer)?;
            writer.write_all(&[0_u8; 3][..pad_len])?;
            writer.write_u32::<B>(block_len)?;

            Ok(block_len as usize)
        }
    }

    /// Tries to downcasts the current block into an [`EnhancedPacketBlock`]
    pub fn into_enhanced_packet(self) -> Option<EnhancedPacketBlock<'a>> {
        match self {
            Block::EnhancedPacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block as an [`EnhancedPacketBlock`]
    pub fn as_enhanced_packet(&self) -> Option<&EnhancedPacketBlock<'a>> {
        match self {
            Block::EnhancedPacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block into an [`InterfaceDescriptionBlock`]
    pub fn into_interface_description(self) -> Option<InterfaceDescriptionBlock<'a>> {
        match self {
            Block::InterfaceDescription(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block as an [`InterfaceDescriptionBlock`]
    pub fn as_interface_description(&self) -> Option<&InterfaceDescriptionBlock<'a>> {
        match self {
            Block::InterfaceDescription(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block into an [`InterfaceStatisticsBlock`]
    pub fn into_interface_statistics(self) -> Option<InterfaceStatisticsBlock<'a>> {
        match self {
            Block::InterfaceStatistics(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block as an [`InterfaceStatisticsBlock`]
    pub fn as_interface_statistics(&self) -> Option<&InterfaceStatisticsBlock<'a>> {
        match self {
            Block::InterfaceStatistics(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into a [`NameResolutionBlock`], if possible
    pub fn into_name_resolution(self) -> Option<NameResolutionBlock<'a>> {
        match self {
            Block::NameResolution(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block as a [`NameResolutionBlock`], if possible
    pub fn as_name_resolution(&self) -> Option<&NameResolutionBlock<'a>> {
        match self {
            Block::NameResolution(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into a [`PacketBlock`], if possible
    pub fn into_packet(self) -> Option<PacketBlock<'a>> {
        match self {
            Block::Packet(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block as a [`PacketBlock`], if possible
    pub fn as_packet(&self) -> Option<&PacketBlock<'a>> {
        match self {
            Block::Packet(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into a [`SectionHeaderBlock`], if possible
    pub fn into_section_header(self) -> Option<SectionHeaderBlock<'a>> {
        match self {
            Block::SectionHeader(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block as a [`SectionHeaderBlock`], if possible
    pub fn as_section_header(&self) -> Option<&SectionHeaderBlock<'a>> {
        match self {
            Block::SectionHeader(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into a [`SimplePacketBlock`], if possible
    pub fn into_simple_packet(self) -> Option<SimplePacketBlock<'a>> {
        match self {
            Block::SimplePacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block as a [`SimplePacketBlock`], if possible
    pub fn as_simple_packet(&self) -> Option<&SimplePacketBlock<'a>> {
        match self {
            Block::SimplePacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into a [`SystemdJournalExportBlock`], if possible
    pub fn into_systemd_journal_export(self) -> Option<SystemdJournalExportBlock<'a>> {
        match self {
            Block::SystemdJournalExport(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block as a [`SystemdJournalExportBlock`], if possible
    pub fn as_systemd_journal_export(&self) -> Option<&SystemdJournalExportBlock<'a>> {
        match self {
            Block::SystemdJournalExport(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into a copiable [`CustomBlock`], if possible
    pub fn into_custom_copiable(self) -> Option<CustomBlock<'a, true>> {
        match self {
            Block::CustomCopiable(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block as a copiable [`CustomBlock`], if possible
    pub fn as_custom_copiable(&self) -> Option<&CustomBlock<'a, true>> {
        match self {
            Block::CustomCopiable(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into a non-copiable [`CustomBlock`], if possible
    pub fn into_custom_non_copiable(self) -> Option<CustomBlock<'a, false>> {
        match self {
            Block::CustomNonCopiable(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block as a non-copiable [`CustomBlock`], if possible
    pub fn as_custom_non_copiable(&self) -> Option<&CustomBlock<'a, false>> {
        match self {
            Block::CustomNonCopiable(a) => Some(a),
            _ => None,
        }
    }
}

/// Common interface for the PcapNg blocks
pub trait PcapNgBlock<'a> {
    /// Parse a new block from a slice, using a [`PcapNgState`].
    fn from_slice<B: ByteOrder>(state: &PcapNgState, slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockContentParseError>
    where
        Self: std::marker::Sized;

    /// Write the content of a block into a writer, using a [`PcapNgState`].
    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError>;

    /// Convert a block into the [`Block`] enumeration
    fn into_block(self) -> Block<'a>;
}

/// Convert a block type into its name
pub fn block_name(type_: u32) -> &'static str {
    match type_ {
        SECTION_HEADER_BLOCK => "Section Header Block",
        INTERFACE_DESCRIPTION_BLOCK => "Interface Description Block",
        PACKET_BLOCK => "Packet Block",
        SIMPLE_PACKET_BLOCK => "Simple Packet Block",
        NAME_RESOLUTION_BLOCK => "Name Resolution Block",
        INTERFACE_STATISTIC_BLOCK => "Interface Statistics Block",
        ENHANCED_PACKET_BLOCK => "Enhanced Packet Block",
        SYSTEMD_JOURNAL_EXPORT_BLOCK => "Systemd Journal Export Block",
        CUSTOM_BLOCK_COPIABLE => "Custom Block (Copiable)",
        CUSTOM_BLOCK_NON_COPIABLE => "Custom Block (Non-Copiable)",
        _ => "Unknown Block",
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use byteorder_slice::BigEndian;

    use super::{Block, RawBlock, SECTION_HEADER_BLOCK};
    use crate::Endianness;
    use crate::pcapng::PcapNgState;

    #[test]
    fn try_from_raw_block_accepts_owned_bodies() {
        let raw_block = RawBlock {
            type_: SECTION_HEADER_BLOCK,
            initial_len: 28,
            body: Cow::Owned(vec![
                0x1A, 0x2B, 0x3C, 0x4D, // byte-order magic
                0x00, 0x01, // major version
                0x00, 0x00, // minor version
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // section length
            ]),
            trailer_len: 28,
        };

        let block = Block::try_from_raw_block::<BigEndian>(&PcapNgState::default(), raw_block).unwrap();

        match block {
            Block::SectionHeader(block) => {
                assert_eq!(block.endianness, Endianness::Big);
                assert_eq!(block.major_version, 1);
                assert_eq!(block.minor_version, 0);
                assert!(block.options.is_empty());
            },
            other => panic!("expected SectionHeader block, got {other:?}"),
        }
    }
}
