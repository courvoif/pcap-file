use byteorder::{ByteOrder, LittleEndian, BigEndian, ReadBytesExt};
use std::io::{Read, Take, Error as IoError};
use crate::errors::PcapError;
use crate::peek_reader::PeekReader;
use std::borrow::Cow;
use byteorder::WriteBytesExt;
use crate::pcapng::blocks::{SectionHeaderBlock, InterfaceDescriptionBlock, EnhancedPacketBlock, SimplePacketBlock, NameResolutionBlock, InterfaceStatisticsBlock};

#[derive(Clone, Debug)]
pub struct Block<'a> {

    pub(crate) raw: RawBlock<'a>,
    pub(crate) parsed: ParsedBlock<'a>
}

impl Block<'static> {

    pub fn from_reader<R: Read, B: ByteOrder>(reader: &mut R) -> Result<Block<'static>, PcapError> {

        let raw = RawBlock::from_reader::<R, B>(reader)?;
        let slice: &'static [u8] = unsafe {std::mem::transmute(&raw.body[..])};
        let (parsed, _) = ParsedBlock::from_slice::<B>(raw.type_, slice)?;

        let block = Block {
            raw,
            parsed
        };

        Ok(block)
    }
}

impl<'a> Block<'a> {

    pub fn raw(&self) -> &RawBlock<'a> {
        &self.raw
    }

    pub fn parsed(&self) -> &ParsedBlock<'a> {
        &self.parsed
    }

    pub fn section_header(&self) -> Option<&SectionHeaderBlock<'a>> {
        match &self.parsed {
            ParsedBlock::SectionHeader(inner) => Some(inner),
            _ => None
        }
    }

    pub fn interface_description(&self) -> Option<&InterfaceDescriptionBlock<'a>> {
        match &self.parsed {
            ParsedBlock::InterfaceDescription(inner) => Some(inner),
            _ => None
        }
    }

    pub fn enhanced_packet(&self) -> Option<&EnhancedPacketBlock<'a>> {
        match &self.parsed {
            ParsedBlock::EnhancedPacket(inner) => Some(inner),
            _ => None
        }
    }

    pub fn simple_packet(&self) -> Option<&SimplePacketBlock<'a>> {
        match &self.parsed {
            ParsedBlock::SimplePacket(inner) => Some(inner),
            _ => None
        }
    }
}

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
#[derive(Clone, Debug)]
pub struct RawBlock<'a> {
    pub type_: u32,
    pub initial_len: u32,
    pub body: Cow<'a, [u8]>,
    pub trailer_len: u32
}

impl<'a> RawBlock<'a> {

    fn from_reader<R:Read, B: ByteOrder>(reader: &mut R) -> Result<RawBlock<'static>, PcapError> {

        let type_ = reader.read_u32::<B>()?;

        //Special case for the section header because we don't know the endianness yet
        if type_ == 0x0A0D0D0A {
            let initial_len = reader.read_u32::<BigEndian>()?;
            let magic = reader.read_u32::<BigEndian>()?;

            let initial_len = match magic {
                0x1A2B3C4D => initial_len,
                0x4D3C2B1A => initial_len.swap_bytes(),
                _ => return Err(PcapError::InvalidField("SectionHeaderBlock invalid magic number"))
            };

            let mut body = vec![0_u8; initial_len as usize];
            body.write_u32::<BigEndian>(magic)?;
            reader.read_exact(&mut body[2..])?;

            let trailer_len = match magic {
                0x1A2B3C4D => reader.read_u32::<BigEndian>()?,
                0x4D3C2B1A => reader.read_u32::<LittleEndian>()?,
                _ => unreachable!()
            };

            return Ok(
                RawBlock {
                    type_,
                    initial_len,
                    body: Cow::Owned(body),
                    trailer_len
                }
            )
        }

        //Common case
        let initial_len = reader.read_u32::<B>()?;

        let mut body = vec![0_u8; initial_len as usize];
        reader.read_exact(&mut body[2..])?;

        let trailer_len = reader.read_u32::<B>()?;

        if initial_len != trailer_len {
            return Err(PcapError::InvalidField("Block initial_length != trailer_length"))
        }

        Ok(
            RawBlock {
                type_,
                initial_len,
                body: Cow::Owned(body),
                trailer_len
            }
        )
    }

    fn from_slice<B: ByteOrder>(mut slice: &'a[u8]) -> Result<(Self, &[u8]), PcapError> {

        if slice.len() < 12 {
            return Err(PcapError::IncompleteBuffer(12 - slice.len()));
        }

        let type_ = slice.read_u32::<B>()?;

        //Special case for the section header because we don't know the endianness yet
        if type_ == 0x0A0D0D0A {
            let initial_len = slice.read_u32::<BigEndian>()?;

            let body_to_end = slice;

            let magic = slice.read_u32::<BigEndian>()?;

            let initial_len = match magic {
                0x1A2B3C4D => initial_len,
                0x4D3C2B1A => initial_len.swap_bytes(),
                _ => return Err(PcapError::InvalidField("SectionHeaderBlock invalid magic number"))
            };

            if body_to_end.len() < initial_len as usize {
                return Err(PcapError::IncompleteBuffer(initial_len as usize - body_to_end.len()));
            }
            let body = &body_to_end[..initial_len as usize];
            let mut end = &body_to_end[initial_len as usize ..];

            let trailer_len = match magic {
                0x1A2B3C4D => end.read_u32::<BigEndian>()?,
                0x4D3C2B1A => end.read_u32::<LittleEndian>()?,
                _ => unreachable!()
            };

            let raw = RawBlock {
                type_,
                initial_len,
                body: Cow::Borrowed(body),
                trailer_len
            };

            return Ok((raw, end))
        }

        //Common case
        let initial_len = slice.read_u32::<B>()?;

        let mut body = &slice[..initial_len as usize];
        slice = &slice[initial_len as usize ..];

        let trailer_len = slice.read_u32::<B>()?;

        if initial_len != trailer_len {
            return Err(PcapError::InvalidField("Block initial_length != trailer_length"))
        }

        let raw = RawBlock {
            type_,
            initial_len,
            body: Cow::Borrowed(body),
            trailer_len
        };

        Ok((raw, slice))
    }
}

#[derive(Clone, Debug)]
pub enum ParsedBlock<'a> {
    SectionHeader(SectionHeaderBlock<'a>),
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    SimplePacket(SimplePacketBlock<'a>),
    NameResolution(NameResolutionBlock<'a>),
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    EnhancedPacket(EnhancedPacketBlock<'a>),
    Unknown
}

impl<'a> ParsedBlock<'a> {

    pub fn from_slice<B: ByteOrder>(type_: u32, slice: &'a[u8]) -> Result<(Self, &'a[u8]), PcapError> {

        match type_ {

            0x0A0D0D0A => {
                let (block, slice) = SectionHeaderBlock::from_slice(slice)?;
                Ok((ParsedBlock::SectionHeader(block), slice))
            },
            0x00000001 => {
                let (block, slice) = InterfaceDescriptionBlock::from_slice::<B>(slice)?;
                Ok((ParsedBlock::InterfaceDescription(block), slice))
            },
            0x00000003 => {
                let (block, slice) = SimplePacketBlock::from_slice::<B>(slice)?;
                Ok((ParsedBlock::SimplePacket(block), slice))
            },
            0x00000004 => {
                let (block, slice) = NameResolutionBlock::from_slice::<B>(slice)?;
                Ok((ParsedBlock::NameResolution(block), slice))
            },
            0x00000005 => {
                let (block, slice) = InterfaceStatisticsBlock::from_slice::<B>(slice)?;
                Ok((ParsedBlock::InterfaceStatistics(block), slice))
            },
            0x00000006 => {
                let (block, slice) = EnhancedPacketBlock::from_slice::<B>(slice)?;
                Ok((ParsedBlock::EnhancedPacket(block), slice))
            }
            _ => Ok((ParsedBlock::Unknown, slice))
        }
    }
}

pub(crate) fn opts_from_slice<'a, B, F, O>(mut slice: &'a [u8], func: F) -> Result<(Vec<O>, &'a [u8]), PcapError>
    where B: ByteOrder,
          F: Fn(&'a [u8], u8, usize) -> Result<O, PcapError>

{
    let mut options = vec![];

    // If there is nothing left in the slice, it means that there is no more options
    if slice.is_empty() {
        return Ok((options, slice))
    }

    let mut type_ = 1;
    while type_ != 0 {

        if slice.len() < 3 {
            return Err(PcapError::IncompleteBuffer(3 - slice.len()));
        }

        let type_ = slice.read_u8()?;
        let length = slice.read_u16::<B>()? as usize;
        let pad_len = (4 - length % 4) % 4;

        if type_ == 0 {
            return Ok((options, slice));
        }

        if slice.len() < length + pad_len {
            return Err(PcapError::IncompleteBuffer(length + pad_len - slice.len()));
        }

        let mut tmp_slice = &slice[..length];
        let opt = func(&mut tmp_slice, type_, length)?;

        // Jump over the padding
        slice = &slice[length+pad_len..];

        options.push(opt);
    }

    Ok((options, slice))
}


pub(crate) fn read_to_string(reader: &mut impl Read, length: usize)-> Result<String, IoError> {

    let mut string = String::with_capacity(length);
    reader.read_to_string(&mut string)?;

    Ok(string)
}

pub(crate) fn read_to_vec(reader: &mut impl Read, length: usize)-> Result<Vec<u8>, IoError> {

    let mut vec = Vec::with_capacity(length);
    reader.read_to_end(&mut vec)?;

    Ok(vec)
}
