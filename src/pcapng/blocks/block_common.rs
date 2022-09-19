use std::io::{Result as IoResult, Write};

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};
use derive_into_owned::IntoOwned;

use crate::errors::PcapError;
use crate::pcapng::blocks::{
    EnhancedPacketBlock, InterfaceDescriptionBlock, InterfaceStatisticsBlock, NameResolutionBlock, SectionHeaderBlock, SimplePacketBlock,
    SystemdJournalExportBlock,
};
use crate::pcapng::{PacketBlock, UnknownBlock};
use crate::Endianness;

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
    pub body: &'a [u8],
    /// Trailer length field
    pub trailer_len: u32,
}

impl<'a> RawBlock<'a> {
    /// Create an "borrowed" `Block` from a slice
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 12 {
            return Err(PcapError::IncompleteBuffer(12 - slice.len()));
        }

        let type_ = slice.read_u32::<B>()?;

        //Special case for the section header because we don't know the endianness yet
        if type_ == 0x0A0D0D0A {
            let mut initial_len = slice.read_u32::<BigEndian>()?;

            let mut tmp_slice = slice;

            let magic = tmp_slice.read_u32::<BigEndian>()?;

            let endianness = match magic {
                0x1A2B3C4D => Endianness::Big,
                0x4D3C2B1A => Endianness::Little,
                _ => return Err(PcapError::InvalidField("SectionHeaderBlock: invalid magic number")),
            };

            if endianness == Endianness::Little {
                initial_len = initial_len.swap_bytes();
            }

            if (initial_len % 4) != 0 {
                return Err(PcapError::InvalidField("Block: (initial_len % 4) != 0"));
            }

            if initial_len < 12 {
                return Err(PcapError::InvalidField("Block: initial_len < 12"));
            }

            //Check if there is enough data for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(PcapError::IncompleteBuffer(initial_len as usize - 8 - slice.len()));
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize..];

            let trailer_len = match endianness {
                Endianness::Big => rem.read_u32::<BigEndian>()?,
                Endianness::Little => rem.read_u32::<LittleEndian>()?,
            };

            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block: initial_length != trailer_length"));
            }

            let block = RawBlock { type_, initial_len, body, trailer_len };

            Ok((rem, block))
        }
        else {
            //Common case
            let initial_len = slice.read_u32::<B>()?;

            if (initial_len % 4) != 0 {
                return Err(PcapError::InvalidField("Block: (initial_len % 4) != 0"));
            }

            if initial_len < 12 {
                return Err(PcapError::InvalidField("Block: initial_len < 12"));
            }

            //Check if there is enough data for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(PcapError::IncompleteBuffer(initial_len as usize - 8 - slice.len()));
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize..];

            let trailer_len = rem.read_u32::<B>()?;

            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block initial_length != trailer_length"));
            }

            let block = RawBlock { type_, initial_len, body, trailer_len };

            Ok((rem, block))
        }
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
    /// Unknown block
    Unknown(UnknownBlock<'a>),
}

impl<'a> Block<'a> {
    /// Create a `ParsedBlock` from a slice
    pub fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        let (rem, raw_block) = RawBlock::from_slice::<B>(slice)?;

        let block = match raw_block.type_ {
            0x0A0D0D0A => {
                let (_, block) = SectionHeaderBlock::from_slice::<BigEndian>(raw_block.body)?;
                Block::SectionHeader(block)
            },
            0x00000001 => {
                let (_, block) = InterfaceDescriptionBlock::from_slice::<B>(raw_block.body)?;
                Block::InterfaceDescription(block)
            },
            0x00000002 => {
                let (_, block) = PacketBlock::from_slice::<B>(raw_block.body)?;
                Block::Packet(block)
            },
            0x00000003 => {
                let (_, block) = SimplePacketBlock::from_slice::<B>(raw_block.body)?;
                Block::SimplePacket(block)
            },
            0x00000004 => {
                let (_, block) = NameResolutionBlock::from_slice::<B>(raw_block.body)?;
                Block::NameResolution(block)
            },
            0x00000005 => {
                let (_, block) = InterfaceStatisticsBlock::from_slice::<B>(raw_block.body)?;
                Block::InterfaceStatistics(block)
            },
            0x00000006 => {
                let (_, block) = EnhancedPacketBlock::from_slice::<B>(raw_block.body)?;
                Block::EnhancedPacket(block)
            },
            0x00000009 => {
                let (_, block) = SystemdJournalExportBlock::from_slice::<B>(raw_block.body)?;
                Block::SystemdJournalExport(block)
            },
            type_ => Block::Unknown(UnknownBlock::new(type_, raw_block.initial_len, raw_block.body)),
        };

        Ok((rem, block))
    }

    /// Writes the `Block` to a writer.
    ///
    /// Uses the endianness of the header.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        return match self {
            Self::SectionHeader(b) => inner_write_to::<B, _, W>(b, 0x0A0D0D0A, writer),
            Self::InterfaceDescription(b) => inner_write_to::<B, _, W>(b, 0x00000001, writer),
            Self::Packet(b) => inner_write_to::<B, _, W>(b, 0x00000002, writer),
            Self::SimplePacket(b) => inner_write_to::<B, _, W>(b, 0x00000003, writer),
            Self::NameResolution(b) => inner_write_to::<B, _, W>(b, 0x00000004, writer),
            Self::InterfaceStatistics(b) => inner_write_to::<B, _, W>(b, 0x00000005, writer),
            Self::EnhancedPacket(b) => inner_write_to::<B, _, W>(b, 0x00000006, writer),
            Self::SystemdJournalExport(b) => inner_write_to::<B, _, W>(b, 0x00000009, writer),
            Self::Unknown(b) => inner_write_to::<B, _, W>(b, b.type_, writer),
        };

        fn inner_write_to<'a, B: ByteOrder, BL: PcapNgBlock<'a>, W: Write>(block: &BL, block_code: u32, writer: &mut W) -> IoResult<usize> {
            let data_len = block.write_to::<B, _>(&mut std::io::sink()).unwrap();
            let pad_len = (4 - (data_len % 4)) % 4;

            let block_len = data_len + pad_len + 12;

            writer.write_u32::<B>(block_code)?;
            writer.write_u32::<B>(block_len as u32)?;
            block.write_to::<B, _>(writer)?;
            writer.write_all(&[0_u8; 3][..pad_len])?;
            writer.write_u32::<B>(block_len as u32)?;

            Ok(block_len)
        }
    }

    /// Returns the code of the block
    pub fn block_type_code(&self) -> u32 {
        match self {
            Self::SectionHeader(_) => 0x0A0D0D0A,
            Self::InterfaceDescription(_) => 0x00000001,
            Self::Packet(_) => 0x00000002,
            Self::SimplePacket(_) => 0x00000003,
            Self::NameResolution(_) => 0x00000004,
            Self::InterfaceStatistics(_) => 0x00000005,
            Self::EnhancedPacket(_) => 0x00000006,
            Self::SystemdJournalExport(_) => 0x00000009,
            Self::Unknown(c) => c.type_,
        }
    }

    /// Downcast the current block into an [`EnhancedPacketBlock`], if possible
    pub fn into_enhanced_packet(self) -> Option<EnhancedPacketBlock<'a>> {
        match self {
            Block::EnhancedPacket(a) => Some(a),
            _ => None,
        }
    }

    /// Downcast the current block into an [`InterfaceDescriptionBlock`], if possible
    pub fn into_interface_description(self) -> Option<InterfaceDescriptionBlock<'a>> {
        match self {
            Block::InterfaceDescription(a) => Some(a),
            _ => None,
        }
    }

    /// Downcast the current block into an [`InterfaceStatisticsBlock`], if possible
    pub fn into_interface_statistics(self) -> Option<InterfaceStatisticsBlock<'a>> {
        match self {
            Block::InterfaceStatistics(a) => Some(a),
            _ => None,
        }
    }

    /// Downcast the current block into an [`NameResolutionBlock`], if possible
    pub fn into_name_resolution(self) -> Option<NameResolutionBlock<'a>> {
        match self {
            Block::NameResolution(a) => Some(a),
            _ => None,
        }
    }

    /// Downcast the current block into an [`PacketBlock`], if possible
    pub fn into_packet(self) -> Option<PacketBlock<'a>> {
        match self {
            Block::Packet(a) => Some(a),
            _ => None,
        }
    }

    /// Downcast the current block into an [`SectionHeaderBlock`], if possible
    pub fn into_section_header(self) -> Option<SectionHeaderBlock<'a>> {
        match self {
            Block::SectionHeader(a) => Some(a),
            _ => None,
        }
    }

    /// Downcast the current block into an [`SimplePacketBlock`], if possible
    pub fn into_simple_packet(self) -> Option<SimplePacketBlock<'a>> {
        match self {
            Block::SimplePacket(a) => Some(a),
            _ => None,
        }
    }

    /// Downcast the current block into an [`SystemdJournalExportBlock`], if possible
    pub fn into_systemd_journal_export(self) -> Option<SystemdJournalExportBlock<'a>> {
        match self {
            Block::SystemdJournalExport(a) => Some(a),
            _ => None,
        }
    }
}


/// Common interface for the PcapNg blocks
pub trait PcapNgBlock<'a> {
    /// Parse a new block from a slice
    fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&[u8], Self), PcapError>
    where
        Self: std::marker::Sized;

    /// Write the content of a block into a writer
    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize>;

    /// Convert a block into the [`Block`] enumeration
    fn into_block(self) -> Block<'a>;
}
