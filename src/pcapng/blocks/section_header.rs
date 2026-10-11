//! [`Section Header Block`](SectionHeaderBlock).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{
    CommonOption, PcapNgOption, opts_from_slice, validate_opts, validate_unique_opts, write_bytes_option, write_opts_to,
};
use crate::Endianness;
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, OptionEntryError, WriteError};

/* ----- SectionHeaderBlock ----- */

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
    /// large files.
    /// Length of -1i64 means that the length is unspecified.
    pub section_length: i64,

    /// Options
    pub options: Vec<SectionHeaderOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for SectionHeaderBlock<'a> {
    /// Numeric type code of this block.
    const TYPE: u32 = 0x0A0D0D0A;
    /// Human-readable name of this block.
    const NAME: &'static str = "Section Header Block";
    /// Checks the constraints applicable to this value.
    fn validate(&self, state: &PcapNgState) -> Result<(), BlockValidationError> {
        validate_unique_opts(&self.options, |option| {
            !matches!(option, SectionHeaderOption::Common(_))
        })
        .map_err(BlockValidationError::Option)?;

        validate_opts(&self.options, state, None).map_err(BlockValidationError::Option)
    }

    /// Decodes this block body using the supplied section state.
    fn from_body<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError> {
        /// Decodes the selected typed block body.
        fn parse_body<'a, B: ByteOrder>(
            state: &PcapNgState,
            endianness: Endianness,
            mut slice: &'a [u8],
        ) -> Result<(&'a [u8], SectionHeaderBlock<'a>), BlockValidationError> {
            let major_version = slice.read_u16::<B>().unwrap();
            let minor_version = slice.read_u16::<B>().unwrap();
            let section_length = slice.read_i64::<B>().unwrap();

            let (rem, options) = opts_from_slice::<B, SectionHeaderOption>(state, None, slice)?;
            let block = SectionHeaderBlock {
                endianness,
                major_version,
                minor_version,
                section_length,
                options,
            };

            Ok((rem, block))
        }

        // Start of implementation
        if slice.len() < 16 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 16,
                actual: slice.len(),
            });
        }

        let magic = slice.read_u32::<BigEndian>().unwrap();
        match magic {
            0x1A2B3C4D => parse_body::<BigEndian>(state, Endianness::Big, slice),
            0x4D3C2B1A => parse_body::<LittleEndian>(state, Endianness::Little, slice),
            _ => Err(BlockValidationError::InvalidMagicNumber(magic)),
        }
    }

    /// Writes this block body using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        match self.endianness {
            Endianness::Big => writer.write_u32::<BigEndian>(0x1A2B3C4D)?,
            Endianness::Little => writer.write_u32::<LittleEndian>(0x1A2B3C4D)?,
        };

        writer.write_u16::<B>(self.major_version)?;
        writer.write_u16::<B>(self.minor_version)?;
        writer.write_i64::<B>(self.section_length)?;

        let opt_len = write_opts_to::<B, _, W>(&self.options, state, None, writer)
            .map_err(|error| error.map_other(BlockValidationError::Option))?;

        Ok(16 + opt_len)
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::SectionHeader(self)
    }
}

/* ----- Tests ----- */

/// Checks this module's capture behavior.
#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use byteorder_slice::BigEndian;

    use super::{SectionHeaderBlock, SectionHeaderOption};
    use crate::Endianness;
    use crate::pcapng::PcapNgState;
    use crate::pcapng::blocks::PcapNgBlock;

    /* ----- Section byte order ----- */

    /// Checks that section magic determines the option byte order.
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

        let (_, block) = SectionHeaderBlock::from_body::<BigEndian>(&PcapNgState::default(), &body).unwrap();

        assert_eq!(block.endianness, Endianness::Little);
        assert_eq!(block.major_version, 1);
        assert_eq!(block.minor_version, 0);
        assert_eq!(block.options, vec![SectionHeaderOption::OS("linux-x6".into())]);
    }
}

impl Default for SectionHeaderBlock<'static> {
    /// Returns the default capture settings.
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

/* ----- SectionHeaderOption ----- */

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
    /// Encoded option code for `HARDWARE`.
    const HARDWARE: u16 = 2;
    /// Encoded option code for `OS_`.
    const OS_: u16 = 3;
    /// Encoded option code for `USER_APPLICATION`.
    const USER_APPLICATION: u16 = 4;
}

impl<'a> PcapNgOption<'a> for SectionHeaderOption<'a> {
    /// Decodes an option value for the supplied option code.
    fn from_content<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::HARDWARE => SectionHeaderOption::Hardware(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::OS_ => SectionHeaderOption::OS(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::USER_APPLICATION => SectionHeaderOption::UserApplication(Cow::Borrowed(std::str::from_utf8(slice)?)),

            _ => SectionHeaderOption::Common(CommonOption::from_content::<B>(code, slice)?),
        };

        Ok(opt)
    }

    /// Writes this value using the selected byte order.
    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        match self {
            SectionHeaderOption::Hardware(a) => write_bytes_option::<B, W>(writer, Self::HARDWARE, a.as_bytes()),
            SectionHeaderOption::OS(a) => write_bytes_option::<B, W>(writer, Self::OS_, a.as_bytes()),
            SectionHeaderOption::UserApplication(a) => {
                write_bytes_option::<B, W>(writer, Self::USER_APPLICATION, a.as_bytes())
            }
            SectionHeaderOption::Common(a) => a.write_to::<B, W>(writer),
        }
    }

    /// Checks the constraints applicable to this value.
    fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError> {
        Ok(())
    }

    /// Returns the encoded option code.
    fn code(&self) -> u16 {
        match self {
            Self::Hardware(_) => Self::HARDWARE,
            Self::OS(_) => Self::OS_,
            Self::UserApplication(_) => Self::USER_APPLICATION,
            Self::Common(option) => option.code(),
        }
    }

    /// Returns the option name for its code.
    fn name(code: u16) -> &'static str {
        match code {
            Self::HARDWARE => "Hardware",
            Self::OS_ => "OS",
            Self::USER_APPLICATION => "UserApplication",
            _ => CommonOption::code_name(code),
        }
    }
}
