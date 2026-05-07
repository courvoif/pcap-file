//! Section Header Block.

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOpt};
use crate::Endianness;
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockContentParseError, ContentValidationError, OptionEntryError, PcapNgWriteError};

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
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockContentParseError> {
        fn parse_body<'a, B: ByteOrder>(
            state: &PcapNgState,
            endianness: Endianness,
            mut slice: &'a [u8],
        ) -> Result<(&'a [u8], SectionHeaderBlock<'a>), BlockContentParseError> {
            let major_version = slice.read_u16::<B>().unwrap();
            let minor_version = slice.read_u16::<B>().unwrap();
            let section_length = slice.read_i64::<B>().unwrap();

            let (rem, options) = SectionHeaderOption::opts_from_slice::<B>(state, None, slice)?;
            let block = SectionHeaderBlock { endianness, major_version, minor_version, section_length, options };

            Ok((rem, block))
        }

        // Start of implementation
        if slice.len() < 16 {
            return Err(BlockContentParseError::BlockContentTooSmall { needed: 16, actual: slice.len() });
        }

        let magic = slice.read_u32::<BigEndian>().unwrap();
        match magic {
            0x1A2B3C4D => parse_body::<BigEndian>(state, Endianness::Big, slice),
            0x4D3C2B1A => parse_body::<LittleEndian>(state, Endianness::Little, slice),
            _ => Err(ContentValidationError::InvalidMagicNumber(magic).into()),
        }
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
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

#[cfg(test)]
mod tests {
    use byteorder_slice::BigEndian;

    use super::{SectionHeaderBlock, SectionHeaderOption};
    use crate::Endianness;
    use crate::pcapng::PcapNgState;
    use crate::pcapng::blocks::PcapNgBlock;

    #[test]
    fn parses_little_endian_options_using_magic_number() {
        let body = [
            0x4D, 0x3C, 0x2B, 0x1A, // little-endian magic number
            0x01, 0x00, // major version
            0x00, 0x00, // minor version
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // section length = -1
            0x03, 0x00, // shb_os
            0x08, 0x00, // option length = 8
            b'l', b'i', b'n', b'u', b'x', b'-', b'x', b'6', 0x00, 0x00, 0x00, 0x00, // opt_endofopt
        ];

        let (_, block) = SectionHeaderBlock::from_slice::<BigEndian>(&PcapNgState::default(), &body).unwrap();

        assert_eq!(block.endianness, Endianness::Little);
        assert_eq!(block.major_version, 1);
        assert_eq!(block.minor_version, 0);
        assert_eq!(block.options, vec![SectionHeaderOption::OS("linux-x6".into())]);
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
    /// Description of the hardware used to create this section
    Hardware(Cow<'a, str>),

    /// Name of the operating system used to create this section
    OS(Cow<'a, str>),

    /// Name of the application used to create this section
    UserApplication(Cow<'a, str>),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl SectionHeaderOption<'_> {
    const HARDWARE: u16 = 2;
    const OS_: u16 = 3;
    const USER_APPLICATION: u16 = 4;
}

impl<'a> PcapNgOption<'a> for SectionHeaderOption<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::HARDWARE => SectionHeaderOption::Hardware(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::OS_ => SectionHeaderOption::OS(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::USER_APPLICATION => SectionHeaderOption::UserApplication(Cow::Borrowed(std::str::from_utf8(slice)?)),

            _ => SectionHeaderOption::Common(CommonOption::new::<B>(code, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError> {
        match self {
            SectionHeaderOption::Hardware(a) => a.write_opt::<B, W>(Self::HARDWARE, writer),
            SectionHeaderOption::OS(a) => a.write_opt::<B, W>(Self::OS_, writer),
            SectionHeaderOption::UserApplication(a) => a.write_opt::<B, W>(Self::USER_APPLICATION, writer),
            SectionHeaderOption::Common(a) => a.write_opt::<B, W>(a.code(), writer),
        }
    }

    fn code_name(code: u16) -> &'static str {
        match code {
            Self::HARDWARE => "Hardware",
            Self::OS_ => "OS",
            Self::USER_APPLICATION => "UserApplication",
            _ => CommonOption::code_name(code),
        }
    }
}
