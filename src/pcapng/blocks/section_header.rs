//! Section Header Block.

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOptTo};
use crate::errors::PcapError;
use crate::pcapng::PcapNgState;
use crate::Endianness;


/// Section Header Block: it defines the most important characteristics of the capture file.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SectionHeaderBlock<'a> {
    /// Endianness of the section.
    pub endianness: Endianness,

    /// Major version of the format.
    /// Current value is 1.
    pub major_version: u16,

    /// Minor version of the format.
    /// Current value is 0.
    pub minor_version: u16,

    /// Length in bytes of the following section excluding this block.
    ///
    /// This block can be used to skip the section for faster navigation in
    /// large files. Length of -1i64 means that the length is unspecified.
    pub section_length: i64,

    /// Options
    pub options: Vec<SectionHeaderOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for SectionHeaderBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 16 {
            return Err(PcapError::InvalidField("SectionHeaderBlock: block length < 16"));
        }

        let magic = slice.read_u32::<BigEndian>().unwrap();
        let endianness = match magic {
            0x1A2B3C4D => Endianness::Big,
            0x4D3C2B1A => Endianness::Little,
            _ => return Err(PcapError::InvalidField("SectionHeaderBlock: invalid magic number")),
        };

        let (rem, major_version, minor_version, section_length, options) = match endianness {
            Endianness::Big => parse_inner::<BigEndian>(state, slice)?,
            Endianness::Little => parse_inner::<LittleEndian>(state, slice)?,
        };

        let block = SectionHeaderBlock { endianness, major_version, minor_version, section_length, options };

        return Ok((rem, block));

        #[allow(clippy::type_complexity)]
        fn parse_inner<'a, B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], u16, u16, i64, Vec<SectionHeaderOption<'a>>), PcapError> {
            let maj_ver = slice.read_u16::<B>().unwrap();
            let min_ver = slice.read_u16::<B>().unwrap();
            let sec_len = slice.read_i64::<B>().unwrap();
            let (rem, opts) = SectionHeaderOption::opts_from_slice::<B>(state, None, slice)?;

            Ok((rem, maj_ver, min_ver, sec_len, opts))
        }
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapError> {
        match self.endianness {
            Endianness::Big => writer.write_u32::<BigEndian>(0x1A2B3C4D)?,
            Endianness::Little => writer.write_u32::<LittleEndian>(0x1A2B3C4D)?,
        };

        writer.write_u16::<B>(self.major_version)?;
        writer.write_u16::<B>(self.minor_version)?;
        writer.write_i64::<B>(self.section_length)?;

        let opt_len = SectionHeaderOption::write_opts_to::<B, W>(&self.options, state, None, writer)?;

        Ok(16 + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::SectionHeader(self)
    }
}

impl Default for SectionHeaderBlock<'static> {
    fn default() -> Self {
        Self {
            endianness: Endianness::Big,
            major_version: 1,
            minor_version: 0,
            section_length: -1,
            options: vec![],
        }
    }
}


/// Section Header Block options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum SectionHeaderOption<'a> {
    /// Comment associated with the current block
    Comment(Cow<'a, str>),

    /// Description of the hardware used to create this section
    Hardware(Cow<'a, str>),

    /// Name of the operating system used to create this section
    OS(Cow<'a, str>),

    /// Name of the application used to create this section
    UserApplication(Cow<'a, str>),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl<'a> PcapNgOption<'a> for SectionHeaderOption<'a> {
    fn from_slice<B: ByteOrder>(_state: &PcapNgState, _interface_id: Option<u32>, code: u16, length: u16, slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => SectionHeaderOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => SectionHeaderOption::Hardware(Cow::Borrowed(std::str::from_utf8(slice)?)),
            3 => SectionHeaderOption::OS(Cow::Borrowed(std::str::from_utf8(slice)?)),
            4 => SectionHeaderOption::UserApplication(Cow::Borrowed(std::str::from_utf8(slice)?)),

            _ => SectionHeaderOption::Common(CommonOption::new::<B>(code, length, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, _state: &PcapNgState, _interface_id: Option<u32>, writer: &mut W) -> Result<usize, PcapError> {
        Ok(match self {
            SectionHeaderOption::Comment(a) => a.write_opt_to::<B, W>(1, writer),
            SectionHeaderOption::Hardware(a) => a.write_opt_to::<B, W>(2, writer),
            SectionHeaderOption::OS(a) => a.write_opt_to::<B, W>(3, writer),
            SectionHeaderOption::UserApplication(a) => a.write_opt_to::<B, W>(4, writer),
            SectionHeaderOption::Common(a) => a.write_opt_to::<B, W>(a.code(), writer),
        }?)
    }
}
