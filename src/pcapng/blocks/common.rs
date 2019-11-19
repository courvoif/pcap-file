use byteorder::{ByteOrder, LittleEndian, BigEndian, ReadBytesExt};
use std::io::Read;
use crate::errors::PcapError;
use std::borrow::Cow;
use byteorder::WriteBytesExt;
use crate::pcapng::blocks::{SectionHeaderBlock, InterfaceDescriptionBlock, EnhancedPacketBlock, SimplePacketBlock, NameResolutionBlock, InterfaceStatisticsBlock, SystemdJournalExportBlock};
use crate::pcapng::PacketBlock;
use crate::Endianness;
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
pub struct Block<'a> {
    pub type_: BlockType,
    pub initial_len: u32,
    pub body: Cow<'a, [u8]>,
    pub trailer_len: u32,
    endianness: Endianness
}

impl<'a> Block<'a> {

    /// Create an "owned" `Block` from a reader
    pub(crate) fn from_reader<R:Read, B: ByteOrder>(reader: &mut R) -> Result<Block<'static>, PcapError> {

        let type_ = reader.read_u32::<B>()?.into();

        //Special case for the section header because we don't know the endianness yet
        if type_ == BlockType::SectionHeader {
            let mut initial_len = reader.read_u32::<BigEndian>()?;
            let magic = reader.read_u32::<BigEndian>()?;

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

            let body_len = initial_len - 12;
            let mut body = vec![0_u8; body_len as usize];
            // Rewrite the magic in the body
            (&mut body[..]).write_u32::<BigEndian>(magic)?;
            reader.read_exact(&mut body[4..])?;

            let trailer_len = match endianness {
                Endianness::Big => reader.read_u32::<BigEndian>()?,
                Endianness::Little => reader.read_u32::<LittleEndian>()?
            };

            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block initial_length != trailer_length"))
            }

            Ok(
                Block {
                    type_,
                    initial_len,
                    body: Cow::Owned(body),
                    trailer_len,
                    endianness
                }
            )
        }
        else {

            //Common case
            let initial_len = reader.read_u32::<B>()?;
            if (initial_len % 4) != 0 {
                return Err(PcapError::InvalidField("Block: (initial_len % 4) != 0"));
            }

            if initial_len < 12 {
                return Err(PcapError::InvalidField("Block: initial_len < 12"))
            }

            let body_len = initial_len - 12;
            let mut body = vec![0_u8; body_len as usize];
            reader.read_exact(&mut body[..])?;

            let trailer_len = reader.read_u32::<B>()?;
            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block initial_length != trailer_length"))
            }

            Ok(
                Block {
                    type_,
                    initial_len,
                    body: Cow::Owned(body),
                    trailer_len,
                    endianness: Endianness::new::<B>()
                }
            )
        }
    }

    /// Create an "borrowed" `Block` from a slice
    pub(crate) fn from_slice<B: ByteOrder>(mut slice: &'a[u8]) -> Result<(&[u8], Self), PcapError> {

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
                return Err(PcapError::InvalidField("Block initial_length != trailer_length"))
            }


            let block = Block {
                type_,
                initial_len,
                body: Cow::Borrowed(body),
                trailer_len,
                endianness
            };

            return Ok((rem, block))
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

            let block = Block {
                type_,
                initial_len,
                body: Cow::Borrowed(body),
                trailer_len,
                endianness: Endianness::new::<B>()
            };

            Ok((rem, block))
        }
    }

    pub fn parsed(&self) -> Result<ParsedBlock, PcapError> {

        match self.endianness {
            Endianness::Big => ParsedBlock::from_slice::<BigEndian>(self.type_, &self.body).map(|r| r.1),
            Endianness::Little => ParsedBlock::from_slice::<LittleEndian>(self.type_, &self.body).map(|r| r.1)
        }
    }
}

/// PcapNg parsed blocks
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

/// PcapNg parsed blocks
#[derive(Clone, Debug, IntoOwned)]
pub enum ParsedBlock<'a> {
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

impl<'a> ParsedBlock<'a> {

    /// Create a `ParsedBlock` from a slice
    pub fn from_slice<B: ByteOrder>(type_: BlockType, slice: &'a[u8]) -> Result<(&'a [u8], Self), PcapError> {

        match type_ {

            BlockType::SectionHeader => {
                let (rem, block) = SectionHeaderBlock::from_slice(slice)?;
                Ok((rem, ParsedBlock::SectionHeader(block)))
            },
            BlockType::InterfaceDescription => {
                let (rem, block) = InterfaceDescriptionBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::InterfaceDescription(block)))
            },
            BlockType::Packet => {
                let (rem, block) = PacketBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::Packet(block)))
            },
            BlockType::SimplePacket => {
                let (rem, block) = SimplePacketBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::SimplePacket(block)))
            },
            BlockType::NameResolution => {
                let (rem, block) = NameResolutionBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::NameResolution(block)))
            },
            BlockType::InterfaceStatistics => {
                let (rem, block) = InterfaceStatisticsBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::InterfaceStatistics(block)))
            },
            BlockType::EnhancedPacket => {
                let (rem, block) = EnhancedPacketBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::EnhancedPacket(block)))
            },
            BlockType::SystemdJournalExport => {
                let (rem, block) = SystemdJournalExportBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::SystemdJournalExport(block)))
            }
            _ => Ok((slice, ParsedBlock::Unknown(UnknownBlock::new(type_, slice.len() as u32, slice))))
        }
    }

    pub fn into_section_header(self) -> Option<SectionHeaderBlock<'a>> {
        match self {
            ParsedBlock::SectionHeader(section) => Some(section),
            _ => None
        }
    }

    pub fn into_interface_description(self) -> Option<InterfaceDescriptionBlock<'a>> {
        match self {
            ParsedBlock::InterfaceDescription(block) => Some(block),
            _ => None
        }
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct UnknownBlock<'a> {
    pub type_: BlockType,
    pub length: u32,
    pub value: Cow<'a, [u8]>
}

impl<'a> UnknownBlock<'a> {
    pub fn new(type_: BlockType, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock {
            type_,
            length,
            value: Cow::Borrowed(value)
        }
    }
}

/// Parse all options in a block
pub(crate) fn opts_from_slice<'a, B, F, O>(mut slice: &'a [u8], func: F) -> Result<(&'a [u8], Vec<O>), PcapError>
    where B: ByteOrder,
          F: Fn(&'a [u8], u16, u16) -> Result<O, PcapError>

{
    let mut options = vec![];

    // If there is nothing left in the slice, it means that there is no option
    if slice.is_empty() {
        return Ok((slice, options))
    }

    loop {

        if slice.len() < 4 {
            return Err(PcapError::InvalidField("Option: slice.len() < 4"));
        }

        let code = slice.read_u16::<B>()?;
        let length = slice.read_u16::<B>()? as usize;
        let pad_len = (4 - (length % 4)) % 4;

        if code == 0 {
            return Ok((slice, options));
        }

        if slice.len() < length + pad_len {
            return Err(PcapError::InvalidField("Option: length + pad.len() > slice.len()"));
        }

        let mut tmp_slice = &slice[..length];
        let opt = func(&mut tmp_slice, code, length as u16)?;

        // Jump over the padding
        slice = &slice[length+pad_len..];

        options.push(opt);
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct UnknownOption<'a> {
    code: u16,
    length: u16,
    value: Cow<'a, [u8]>
}
impl<'a> UnknownOption<'a> {
    pub fn new(code: u16, length: u16, value: &'a[u8]) -> Self {
        UnknownOption {
            code,
            length,
            value: Cow::Borrowed(value)
        }
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct CustomBinaryOption<'a> {
    code: u16,
    pen: u32,
    value: Cow<'a, [u8]>
}
impl<'a> CustomBinaryOption<'a> {
    pub fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<Self, PcapError> {
        let pen = src.read_u32::<B>()?;

        let opt = CustomBinaryOption {
            code,
            pen,
            value: Cow::Borrowed(src)
        };

        Ok(opt)
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct CustomUtf8Option<'a> {
    code: u16,
    pen: u32,
    value: Cow<'a, str>
}
impl<'a> CustomUtf8Option<'a> {
    pub fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<Self, PcapError> {
        let pen = src.read_u32::<B>()?;

        let opt = CustomUtf8Option {
            code,
            pen,
            value: Cow::Borrowed(std::str::from_utf8(src)?)
        };

        Ok(opt)
    }
}