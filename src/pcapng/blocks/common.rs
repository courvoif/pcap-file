use byteorder::{ByteOrder, LittleEndian, BigEndian, ReadBytesExt};
use std::io::Read;
use crate::errors::PcapError;
use std::borrow::Cow;
use byteorder::WriteBytesExt;
use crate::pcapng::blocks::{SectionHeaderBlock, InterfaceDescriptionBlock, EnhancedPacketBlock, SimplePacketBlock, NameResolutionBlock, InterfaceStatisticsBlock, SystemdJournalExportBlock};

#[derive(Clone, Debug)]
pub struct Block<'a> {

    pub(crate) raw: RawBlock<'a>,
    pub(crate) parsed: ParsedBlock<'a>
}

impl Block<'static> {

    pub fn from_reader<R: Read, B: ByteOrder>(reader: &mut R) -> Result<Block<'static>, PcapError> {

        let raw = RawBlock::from_reader::<R, B>(reader)?;
        let slice: &'static [u8] = unsafe {std::mem::transmute(&raw.body[..])};
        let (_, parsed) = ParsedBlock::from_slice::<B>(raw.type_, slice)?;

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

    pub fn parsed<'b>(&'b self) -> &ParsedBlock<'b> {
        &self.parsed
    }

    pub fn section_header<'b>(&'b self) -> Option<&SectionHeaderBlock<'b>> {
        match &self.parsed {
            ParsedBlock::SectionHeader(inner) => Some(inner),
            _ => None
        }
    }

    pub fn interface_description<'b>(&'b self) -> Option<&InterfaceDescriptionBlock<'b>> {
        match &self.parsed {
            ParsedBlock::InterfaceDescription(inner) => Some(inner),
            _ => None
        }
    }

    pub fn simple_packet<'b>(&'b self) -> Option<&SimplePacketBlock<'b>> {
        match &self.parsed {
            ParsedBlock::SimplePacket(inner) => Some(inner),
            _ => None
        }
    }

    pub fn name_resolution<'b>(&'b self) -> Option<&NameResolutionBlock<'b>> {
        match &self.parsed {
            ParsedBlock::NameResolution(inner) => Some(inner),
            _ => None
        }
    }

    pub fn interface_statistics<'b>(&'b self) -> Option<&InterfaceStatisticsBlock<'b>> {
        match &self.parsed {
            ParsedBlock::InterfaceStatistics(inner) => Some(inner),
            _ => None
        }
    }

    pub fn enhanced_packet<'b>(&'b self) -> Option<&EnhancedPacketBlock<'b>> {
        match &self.parsed {
            ParsedBlock::EnhancedPacket(inner) => Some(inner),
            _ => None
        }
    }

    pub fn systemd_journal_export<'b>(&'b self) -> Option<&SystemdJournalExportBlock<'b>> {
        match &self.parsed {
            ParsedBlock::SystemdJournalExport(inner) => Some(inner),
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

    pub fn from_slice<B: ByteOrder>(mut slice: &'a[u8]) -> Result<(Self, &[u8]), PcapError> {

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

        let body = &slice[..initial_len as usize];
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
    SystemdJournalExport(SystemdJournalExportBlock<'a>),
    Unknown
}

impl<'a> ParsedBlock<'a> {

    pub fn from_slice<B: ByteOrder>(type_: u32, slice: &'a[u8]) -> Result<(&'a[u8], Self), PcapError> {

        match type_ {

            0x0A0D0D0A => {
                let (rem, block) = SectionHeaderBlock::from_slice(slice)?;
                Ok((rem, ParsedBlock::SectionHeader(block)))
            },
            0x00000001 => {
                let (rem, block) = InterfaceDescriptionBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::InterfaceDescription(block)))
            },
            0x00000003 => {
                let (rem, block) = SimplePacketBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::SimplePacket(block)))
            },
            0x00000004 => {
                let (rem, block) = NameResolutionBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::NameResolution(block)))
            },
            0x00000005 => {
                let (rem, block) = InterfaceStatisticsBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::InterfaceStatistics(block)))
            },
            0x00000006 => {
                let (rem, block) = EnhancedPacketBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::EnhancedPacket(block)))
            },
            0x00000009 => {
                let (rem, block) = SystemdJournalExportBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::SystemdJournalExport(block)))
            }
            _ => Ok((slice, ParsedBlock::Unknown))
        }
    }
}

pub(crate) fn opts_from_slice<'a, B, F, O>(mut slice: &'a [u8], func: F) -> Result<(&'a [u8], Vec<O>), PcapError>
    where B: ByteOrder,
          F: Fn(&'a [u8], u8, usize) -> Result<O, PcapError>

{
    let mut options = vec![];

    // If there is nothing left in the slice, it means that there is no more options
    if slice.is_empty() {
        return Ok((slice, options))
    }

    loop {

        if slice.len() < 3 {
            return Err(PcapError::InvalidField("Option: slice.len() < 3"));
        }

        let type_ = slice.read_u8()?;
        let length = slice.read_u16::<B>()? as usize;
        let pad_len = (4 - (length % 4)) % 4;

        if type_ == 0 {
            return Ok((slice, options));
        }

        if slice.len() < length + pad_len {
            return Err(PcapError::InvalidField("Option: length + pad.len() < slice.len()"));
        }

        let mut tmp_slice = &slice[..length];
        let opt = func(&mut tmp_slice, type_, length)?;

        // Jump over the padding
        slice = &slice[length+pad_len..];

        options.push(opt);
    }
}