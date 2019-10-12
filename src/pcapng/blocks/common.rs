use byteorder::{ByteOrder, LittleEndian, BigEndian, ReadBytesExt};
use std::io::Read;
use crate::errors::PcapError;
use std::borrow::Cow;
use byteorder::WriteBytesExt;
use crate::pcapng::blocks::{SectionHeaderBlock, InterfaceDescriptionBlock, EnhancedPacketBlock, SimplePacketBlock, NameResolutionBlock, InterfaceStatisticsBlock, SystemdJournalExportBlock};
use crate::pcapng::PacketBlock;
use crate::Endianness;


/// PcapNg Block
#[derive(Clone, Debug)]
pub struct Block<'a> {

    pub(crate) raw: RawBlock<'a>,
    pub(crate) parsed: ParsedBlock<'a>
}

impl Block<'static> {

    /// Create an "owned" `Block` from a reader
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

    /// Create an "borrowed" `Block` from a slice
    pub fn from_slice<B: ByteOrder>(src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapError> {

        let (rem, raw) = RawBlock::from_slice::<B>(src)?;
        let slice: &'static [u8] = unsafe {std::mem::transmute(&raw.body[..])};
        let (_, parsed) = ParsedBlock::from_slice::<B>(raw.type_, slice)?;

        let block = Block {
            raw,
            parsed
        };

        Ok((rem, block))
    }

    /// Get a reference to the raw block data
    pub fn raw(&self) -> &RawBlock<'a> {
        &self.raw
    }

    /// Get a reference to the parsed block data
    pub fn parsed<'b>(&'b self) -> &ParsedBlock<'b> {
        &self.parsed
    }

    pub fn to_owned(&self, endianness: Endianness) -> Block<'static> {

        let raw = self.raw.to_owned();
        let slice: &'static [u8] = unsafe {std::mem::transmute(&raw.body[..])};

        let (_, parsed) = if endianness == Endianness::Little {
            ParsedBlock::from_slice::<LittleEndian>(raw.type_, slice).unwrap()
        }
        else {
            ParsedBlock::from_slice::<BigEndian>(raw.type_, slice).unwrap()
        };

        Block {
            raw,
            parsed
        }
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
/// PcapNg Raw Block
#[derive(Clone, Debug)]
pub struct RawBlock<'a> {
    pub type_: u32,
    pub initial_len: u32,
    pub body: Cow<'a, [u8]>,
    pub trailer_len: u32
}

impl<'a> RawBlock<'a> {

    /// Create an "owned" `RawBlock` from a reader
    fn from_reader<R:Read, B: ByteOrder>(reader: &mut R) -> Result<RawBlock<'static>, PcapError> {

        let type_ = reader.read_u32::<B>()?;

        //Special case for the section header because we don't know the endianness yet
        if type_ == 0x0A0D0D0A {
            let initial_len = reader.read_u32::<BigEndian>()?;
            let magic = reader.read_u32::<BigEndian>()?;

            let initial_len = match magic {
                0x1A2B3C4D => initial_len,
                0x4D3C2B1A => initial_len.swap_bytes(),
                _ => return Err(PcapError::InvalidField("SectionHeaderBlock: invalid magic number"))
            };

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

            let trailer_len = match magic {
                0x1A2B3C4D => reader.read_u32::<BigEndian>()?,
                0x4D3C2B1A => reader.read_u32::<LittleEndian>()?,
                _ => unreachable!()
            };
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
                RawBlock {
                    type_,
                    initial_len,
                    body: Cow::Owned(body),
                    trailer_len
                }
            )
        }
    }

    /// Create an "borrowed" `RawBlock` from a slice
    pub fn from_slice<B: ByteOrder>(mut slice: &'a[u8]) -> Result<(&[u8], Self), PcapError> {

        if slice.len() < 12 {
            return Err(PcapError::IncompleteBuffer(12 - slice.len()));
        }

        let type_ = slice.read_u32::<B>()?;

        //Special case for the section header because we don't know the endianness yet
        if type_ == 0x0A0D0D0A {
            let initial_len = slice.read_u32::<BigEndian>()?;

            let mut tmp_slice = slice;

            let magic = tmp_slice.read_u32::<BigEndian>()?;

            let initial_len = match magic {
                0x1A2B3C4D => initial_len,
                0x4D3C2B1A => initial_len.swap_bytes(),
                _ => return Err(PcapError::InvalidField("SectionHeaderBlock invalid magic number"))
            };

            if slice.len() < initial_len as usize {
                return Err(PcapError::IncompleteBuffer(initial_len as usize - slice.len()));
            }
            let body = &slice[..initial_len as usize];
            let mut end = &slice[initial_len as usize ..];

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

            return Ok((end, raw))
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

        Ok((slice, raw))
    }

    pub fn to_owned(&self) -> RawBlock<'static> {

        let type_ = self.type_;
        let initial_len = self.initial_len;
        let body = Cow::Owned(self.body.as_ref().to_owned());
        let trailer_len = self.trailer_len;

        RawBlock {
            type_,
            initial_len,
            body,
            trailer_len
        }
    }
}


/// PcapNg parsed blocks
#[derive(Clone, Debug)]
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
    pub fn from_slice<B: ByteOrder>(type_: u32, slice: &'a[u8]) -> Result<(&'a [u8], Self), PcapError> {

        match type_ {

            0x0A0D0D0A => {
                let (rem, block) = SectionHeaderBlock::from_slice(slice)?;
                Ok((rem, ParsedBlock::SectionHeader(block)))
            },
            0x00000001 => {
                let (rem, block) = InterfaceDescriptionBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::InterfaceDescription(block)))
            },
            0x00000002 => {
                let (rem, block) = PacketBlock::from_slice::<B>(slice)?;
                Ok((rem, ParsedBlock::Packet(block)))
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
            _ => Ok((slice, ParsedBlock::Unknown(UnknownBlock::new(type_, slice.len() as u32, slice))))
        }
    }
}

#[derive(Clone, Debug)]
pub struct UnknownBlock<'a> {
    pub type_: u32,
    pub length: u32,
    pub value: &'a [u8]
}
impl<'a> UnknownBlock<'a> {
    pub fn new(type_: u32, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock {
            type_,
            length,
            value
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

#[derive(Clone, Debug)]
pub struct UnknownOption<'a> {
    code: u16,
    length: u16,
    value: &'a [u8]
}
impl<'a> UnknownOption<'a> {
    pub fn new(code: u16, length: u16, value: &'a[u8]) -> Self {
        UnknownOption {
            code,
            length,
            value
        }
    }
}

#[derive(Clone, Debug)]
pub struct CustomBinaryOption<'a> {
    code: u16,
    pen: u32,
    value: &'a [u8]
}
impl<'a> CustomBinaryOption<'a> {
    pub fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<Self, PcapError> {
        let pen = src.read_u32::<B>()?;

        let opt = CustomBinaryOption {
            code,
            pen,
            value: src
        };

        Ok(opt)
    }
}

#[derive(Clone, Debug)]
pub struct CustomUtf8Option<'a> {
    code: u16,
    pen: u32,
    value: &'a str
}
impl<'a> CustomUtf8Option<'a> {
    pub fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<Self, PcapError> {
        let pen = src.read_u32::<B>()?;

        let opt = CustomUtf8Option {
            code,
            pen,
            value: std::str::from_utf8(src)?
        };

        Ok(opt)
    }
}