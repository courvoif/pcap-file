use std::io::{Result as IoResult, Write};

use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use byteorder::WriteBytesExt;

use crate::Endianness;
use crate::errors::PcapError;
use crate::pcapng::blocks::{EnhancedPacketBlock, InterfaceDescriptionBlock, InterfaceStatisticsBlock, NameResolutionBlock, SectionHeaderBlock, SimplePacketBlock, SystemdJournalExportBlock};
use crate::pcapng::{PacketBlock, UnknownBlock};

use derive_into_owned::IntoOwned;

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
pub(crate) struct RawBlock<'a> {
    pub type_: BlockType,
    pub initial_len: u32,
    pub body: &'a [u8],
    pub trailer_len: u32
}

impl<'a> RawBlock<'a> {
    /// Create an "borrowed" `Block` from a slice
    pub(crate) fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 12 {
            return Err(PcapError::IncompleteBuffer(12 - slice.len()));
        }

        let type_ = slice.read_u32::<B>()?.into();

        //Special case for the section header because we don't know the endianness yet
        if type_ == BlockType::SectionHeader {
            let mut initial_len = slice.read_u32::<BigEndian>()?;

            let mut tmp_slice = slice;

            let magic = tmp_slice.read_u32::<BigEndian>()?;

            let endianness = match magic {
                0x1A2B3C4D => Endianness::Big,
                0x4D3C2B1A => Endianness::Little,
                _ => return Err(PcapError::InvalidField("SectionHeaderBlock: invalid magic number"))
            };

            if endianness == Endianness::Little {
                initial_len = initial_len.swap_bytes();
            }

            if (initial_len % 4) != 0 {
                return Err(PcapError::InvalidField("Block: (initial_len % 4) != 0"));
            }

            if initial_len < 12 {
                return Err(PcapError::InvalidField("Block: initial_len < 12"))
            }

            //Check if there is enough data for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(PcapError::IncompleteBuffer(initial_len as usize - 8 - slice.len()));
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize ..];

            let trailer_len = match endianness {
                Endianness::Big => rem.read_u32::<BigEndian>()?,
                Endianness::Little => rem.read_u32::<LittleEndian>()?
            };

            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block: initial_length != trailer_length"))
            }

            let block = RawBlock {
                type_,
                initial_len,
                body,
                trailer_len
            };

            Ok((rem, block))
        }
        else {
            //Common case
            let initial_len = slice.read_u32::<B>()?;

            if (initial_len % 4) != 0 {
                return Err(PcapError::InvalidField("Block: (initial_len % 4) != 0"));
            }

            if initial_len < 12 {
                return Err(PcapError::InvalidField("Block: initial_len < 12"))
            }

            //Check if there is enough data for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(PcapError::IncompleteBuffer(initial_len as usize - 8 - slice.len()));
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize ..];

            let trailer_len = rem.read_u32::<B>()?;

            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block initial_length != trailer_length"))
            }

            let block = RawBlock {
                type_,
                initial_len,
                body,
                trailer_len
            };

            Ok((rem, block))
        }
    }

    pub fn write_to<B:ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u32::<B>(self.type_.into())?;
        writer.write_u32::<B>(self.initial_len)?;
        writer.write_all(&self.body[..])?;
        writer.write_u32::<B>(self.trailer_len)?;

        Ok(12 + self.body.len())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockType {
    SectionHeader,
    InterfaceDescription,
    Packet,
    SimplePacket,
    NameResolution,
    InterfaceStatistics,
    EnhancedPacket,
    SystemdJournalExport,
    Unknown(u32)
}

impl From<u32> for BlockType {
    fn from(src: u32) -> Self {
        match src {
            0x0A0D0D0A => BlockType::SectionHeader,
            0x00000001 => BlockType::InterfaceDescription,
            0x00000002 => BlockType::Packet,
            0x00000003 => BlockType::SimplePacket,
            0x00000004 => BlockType::NameResolution,
            0x00000005 => BlockType::InterfaceStatistics,
            0x00000006 => BlockType::EnhancedPacket,
            0x00000009 => BlockType::SystemdJournalExport,
            _ => BlockType::Unknown(src),
        }
    }
}

impl From<BlockType> for u32 {
    fn from(block: BlockType) -> Self {
        match block {
            BlockType::SectionHeader => 0x0A0D0D0A,
            BlockType::InterfaceDescription => 0x00000001,
            BlockType::Packet => 0x00000002,
            BlockType::SimplePacket => 0x00000003,
            BlockType::NameResolution => 0x00000004,
            BlockType::InterfaceStatistics => 0x00000005,
            BlockType::EnhancedPacket => 0x00000006,
            BlockType::SystemdJournalExport => 0x00000009,
            BlockType::Unknown(c) => c,
        }
    }
}

/// PcapNg parsed blocks
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Block<'a> {
    SectionHeader(SectionHeaderBlock<'a>),
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    Packet(PacketBlock<'a>),
    SimplePacket(SimplePacketBlock<'a>),
    NameResolution(NameResolutionBlock<'a>),
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    EnhancedPacket(EnhancedPacketBlock<'a>),
    SystemdJournalExport(SystemdJournalExportBlock<'a>),
    Unknown(UnknownBlock<'a>)
}

impl<'a> Block<'a> {
    /// Create a `ParsedBlock` from a slice
    pub fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        let (rem, raw_block) = RawBlock::from_slice::<B>(slice)?;

        let block = match raw_block.type_ {
            BlockType::SectionHeader => {
                let (_, block) = SectionHeaderBlock::from_slice::<BigEndian>(raw_block.body)?;
                Block::SectionHeader(block)
            },
            BlockType::InterfaceDescription => {
                let (_, block) = InterfaceDescriptionBlock::from_slice::<B>(raw_block.body)?;
                Block::InterfaceDescription(block)
            },
            BlockType::Packet => {
                let (_, block) = PacketBlock::from_slice::<B>(raw_block.body)?;
                Block::Packet(block)
            },
            BlockType::SimplePacket => {
                let (_, block) = SimplePacketBlock::from_slice::<B>(raw_block.body)?;
                Block::SimplePacket(block)
            },
            BlockType::NameResolution => {
                let (_, block) = NameResolutionBlock::from_slice::<B>(raw_block.body)?;
                Block::NameResolution(block)
            },
            BlockType::InterfaceStatistics => {
                let (_, block) = InterfaceStatisticsBlock::from_slice::<B>(raw_block.body)?;
                Block::InterfaceStatistics(block)
            },
            BlockType::EnhancedPacket => {
                let (_, block) = EnhancedPacketBlock::from_slice::<B>(raw_block.body)?;
                Block::EnhancedPacket(block)
            },
            BlockType::SystemdJournalExport => {
                let (_, block) = SystemdJournalExportBlock::from_slice::<B>(raw_block.body)?;
                Block::SystemdJournalExport(block)
            },
            _ => Block::Unknown(UnknownBlock::new(raw_block.type_, raw_block.initial_len, raw_block.body))
        };

        Ok((rem, block))
    }

    pub fn into_enhanced_packet(self) -> Option<EnhancedPacketBlock<'a>> {
        match self {
            Block::EnhancedPacket(a) => Some(a),
            _ => None
        }
    }

    pub fn into_interface_description(self) -> Option<InterfaceDescriptionBlock<'a>> {
        match self {
            Block::InterfaceDescription(a) => Some(a),
            _ => None
        }
    }

    pub fn into_interface_statistics(self) -> Option<InterfaceStatisticsBlock<'a>> {
        match self {
            Block::InterfaceStatistics(a) => Some(a),
            _ => None
        }
    }

    pub fn into_name_resolution(self) -> Option<NameResolutionBlock<'a>> {
        match self {
            Block::NameResolution(a) => Some(a),
            _ => None
        }
    }

    pub fn into_packet(self) -> Option<PacketBlock<'a>> {
        match self {
            Block::Packet(a) => Some(a),
            _ => None
        }
    }

    pub fn into_section_header(self) -> Option<SectionHeaderBlock<'a>> {
        match self {
            Block::SectionHeader(a) => Some(a),
            _ => None
        }
    }

    pub fn into_simple_packet(self) -> Option<SimplePacketBlock<'a>> {
        match self {
            Block::SimplePacket(a) => Some(a),
            _ => None
        }
    }

    pub fn into_systemd_journal_export(self) -> Option<SystemdJournalExportBlock<'a>> {
        match self {
            Block::SystemdJournalExport(a) => Some(a),
            _ => None
        }
    }
}

pub(crate) trait PcapNgBlock<'a> {

    const BLOCK_TYPE: BlockType;

    fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&[u8], Self), PcapError> where Self: std::marker::Sized;
    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize>;

    fn write_block_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        let len = self.write_to::<B, _>(&mut std::io::sink()).unwrap() + 12;

        writer.write_u32::<B>( Self::BLOCK_TYPE.into())?;
        writer.write_u32::<B>(len as u32)?;
        self.write_to::<B, _>(writer)?;
        writer.write_u32::<B>(len as u32)?;

        Ok(len)
    }

    fn into_parsed(self) -> Block<'a>;
}


