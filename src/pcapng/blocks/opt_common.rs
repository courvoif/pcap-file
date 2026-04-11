//! Generic block option types.

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use crate::pcapng::blocks::custom::{CustomCopiable, CustomError, CustomNonCopiable};
use crate::pcapng::errors::{OptionEntryError, OptionParseError, PcapNgWriteError};
use crate::pcapng::{ContentValidationError, PcapNgState};

/// Comment
pub const COMMENT: u16 = 0x0001;
/// Custom UTF-8 option code, copiable
pub const CUSTOM_UTF8_OPTION_COPIABLE: u16 = 0x0BAC;
/// Custom UTF-8 option code, non-copiable
pub const CUSTOM_UTF8_OPTION_NON_COPIABLE: u16 = 0x4BAC;
/// Custom binary option code, copiable
pub const CUSTOM_BINARY_OPTION_COPIABLE: u16 = 0x0BAD;
/// Custom binary option code, non-copiable
pub const CUSTOM_BINARY_OPTION_NON_COPIABLE: u16 = 0x4BAD;

/// Common options applicable to all block types.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum CommonOption<'a> {
    /// Comment
    Comment(Cow<'a, str>),

    /// Custom option containing copiable binary octets in the Custom Data portion
    CustomBinaryCopiable(CustomBinaryOption<'a, true>),

    /// Custom option containing non-copiable binary octets in the Custom Data portion
    CustomBinaryNonCopiable(CustomBinaryOption<'a, false>),

    /// Custom option containing a copiable UTF-8 string in the Custom Data portion
    CustomUtf8Copiable(CustomUtf8Option<'a, true>),

    /// Custom option containing a non-copiable UTF-8 string in the Custom Data portion
    CustomUtf8NonCopiable(CustomUtf8Option<'a, false>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

impl<'a> CommonOption<'a> {
    pub(crate) fn code(&self) -> u16 {
        match self {
            CommonOption::Comment(_) => COMMENT,
            CommonOption::CustomBinaryCopiable(_) => CUSTOM_BINARY_OPTION_COPIABLE,
            CommonOption::CustomBinaryNonCopiable(_) => CUSTOM_BINARY_OPTION_NON_COPIABLE,
            CommonOption::CustomUtf8Copiable(_) => CUSTOM_UTF8_OPTION_COPIABLE,
            CommonOption::CustomUtf8NonCopiable(_) => CUSTOM_UTF8_OPTION_NON_COPIABLE,
            CommonOption::Unknown(a) => a.code,
        }
    }

    pub(crate) fn new<B: ByteOrder>(code: u16, slice: &'a [u8]) -> Result<Self, OptionEntryError> {
        Ok(match code {
            COMMENT => CommonOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            CUSTOM_UTF8_OPTION_COPIABLE => CommonOption::CustomUtf8Copiable(CustomUtf8Option::from_slice::<B>(slice)?),
            CUSTOM_UTF8_OPTION_NON_COPIABLE => CommonOption::CustomUtf8NonCopiable(CustomUtf8Option::from_slice::<B>(slice)?),
            CUSTOM_BINARY_OPTION_COPIABLE => CommonOption::CustomBinaryCopiable(CustomBinaryOption::from_slice::<B>(slice)?),
            CUSTOM_BINARY_OPTION_NON_COPIABLE => CommonOption::CustomBinaryNonCopiable(CustomBinaryOption::from_slice::<B>(slice)?),
            _ => CommonOption::Unknown(UnknownOption::new(code, slice)),
        })
    }

    pub(crate) fn code_name(code: u16) -> &'static str {
        match code {
            COMMENT => "Comment",
            CUSTOM_UTF8_OPTION_COPIABLE => "CustomUtf8Copiable",
            CUSTOM_UTF8_OPTION_NON_COPIABLE => "CustomUtf8NonCopiable",
            CUSTOM_BINARY_OPTION_COPIABLE => "CustomBinaryCopiable",
            CUSTOM_BINARY_OPTION_NON_COPIABLE => "CustomBinaryNonCopiable",
            _ => "Unknown",
        }
    }
}

impl<'a> CustomBinaryOption<'a, true> {
    /// Converts this option's value into a type that implements [`CustomCopiable`].
    pub fn interpret<T: CustomCopiable<'a>>(&'a self) -> Result<Option<T>, CustomError> {
        if self.pen != T::PEN {
            return Ok(None);
        }

        T::from_slice(&self.value).map_err(|e| CustomError { pen: T::PEN, src: e.into() })
    }

    /// Converts this option into a [`CommonOption`].
    pub fn into_common_option(self) -> CommonOption<'a> {
        CommonOption::CustomBinaryCopiable(self)
    }
}

impl<'a> CustomBinaryOption<'a, false> {
    /// Converts this option's value into a type that implements [`CustomNonCopiable`].
    pub fn interpret<T: CustomNonCopiable<'a>>(&'a self, state: &T::State) -> Result<Option<T>, CustomError> {
        if self.pen != T::PEN {
            return Ok(None);
        }

        T::from_slice(state, &self.value).map_err(|e| CustomError { pen: T::PEN, src: e.into() })
    }

    /// Converts this option into a [`CommonOption`].
    pub fn into_common_option(self) -> CommonOption<'a> {
        CommonOption::CustomBinaryNonCopiable(self)
    }
}

/// Common fonctions of the PcapNg options
pub(crate) trait PcapNgOption<'a> {
    /// Parse an option from a slice
    fn from_slice<B: ByteOrder>(
        state: &PcapNgState,
        interface_id: Option<u32>,
        code: u16,
        slice: &'a [u8],
    ) -> Result<Self, OptionEntryError>
    where
        Self: std::marker::Sized;

    /// Return the name of the Option entry from its code
    fn code_name(code: u16) -> &'static str;

    /// Parse all options in a block
    fn opts_from_slice<B: ByteOrder>(
        state: &PcapNgState,
        interface_id: Option<u32>,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Vec<Self>), OptionParseError>
    where
        Self: std::marker::Sized,
    {
        let mut options = vec![];

        // If there is nothing left in the slice, it means that there is no option
        if slice.is_empty() {
            return Ok((slice, options));
        }

        while !slice.is_empty() {
            if slice.len() < 4 {
                return Err(OptionParseError::OptionsContentTooSmall { needed: 4, actual: slice.len() });
            }

            let code = slice.read_u16::<B>().expect("available length checked before");
            let length = slice.read_u16::<B>().expect("available length checked before") as usize;
            let pad_len = (4 - (length % 4)) % 4;

            if code == 0 {
                return Ok((slice, options));
            }

            if slice.len() < length + pad_len {
                return Err(OptionParseError::OptionsContentTooSmall { needed: length + pad_len, actual: slice.len() });
            }

            let tmp_slice = &slice[..length];
            let opt = Self::from_slice::<B>(state, interface_id, code, tmp_slice).map_err(|e| OptionParseError::InvalidEntry {
                code,
                name: Self::code_name(code),
                source: e,
            })?;

            // Jump over the padding
            slice = &slice[length + pad_len..];

            options.push(opt);
        }

        Ok((slice, options))
    }

    /// Write the option to a writer
    fn write_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError>;

    /// Write all options in a block
    fn write_opts_to<B: ByteOrder, W: Write>(
        opts: &[Self],
        state: &PcapNgState,
        interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError>
    where
        Self: std::marker::Sized,
    {
        let mut have_opt = false;
        let mut written = 0;
        for opt in opts {
            written += opt.write_to::<B, W>(state, interface_id, writer)?;
            have_opt = true;
        }

        if have_opt {
            writer.write_u16::<B>(0)?;
            writer.write_u16::<B>(0)?;
            written += 4;
        }

        Ok(written)
    }
}

/// Unknown options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownOption<'a> {
    /// Option code
    pub code: u16,
    /// Option value
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownOption<'a> {
    /// Creates a new [`UnknownOption`]
    pub fn new(code: u16, value: &'a [u8]) -> Self {
        UnknownOption { code, value: Cow::Borrowed(value) }
    }
}

/// Custom binary option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomBinaryOption<'a, const COPIABLE: bool> {
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, [u8]>,
}

impl<'a, const COPIABLE: bool> CustomBinaryOption<'a, COPIABLE> {
    /// Parse an [`CustomBinaryOption`] from a slice
    pub fn from_slice<B: ByteOrder>(mut src: &'a [u8]) -> Result<Self, OptionEntryError> {
        let pen = src.read_u32::<B>().map_err(|_| OptionEntryError::WrongSize { expected: 4, actual: src.len() })?;
        let opt = CustomBinaryOption { pen, value: Cow::Borrowed(src) };
        Ok(opt)
    }

    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomBinaryOption<'static, COPIABLE> {
        CustomBinaryOption { pen: self.pen, value: Cow::Owned(self.value.into_owned()) }
    }
}

/// Custom string (UTF-8) option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomUtf8Option<'a, const COPIABLE: bool> {
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, str>,
}

impl<'a, const COPIABLE: bool> CustomUtf8Option<'a, COPIABLE> {
    /// Parse a [`CustomUtf8Option`] from a slice
    pub fn from_slice<B: ByteOrder>(mut src: &'a [u8]) -> Result<Self, OptionEntryError> {
        let pen = src.read_u32::<B>().map_err(|_| OptionEntryError::WrongSize { expected: 4, actual: src.len() })?;
        let opt = CustomUtf8Option { pen, value: Cow::Borrowed(std::str::from_utf8(src)?) };
        Ok(opt)
    }

    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomUtf8Option<'static, COPIABLE> {
        CustomUtf8Option { pen: self.pen, value: Cow::Owned(self.value.into_owned()) }
    }
}

// TODO: rename as WriteOpt
// TODO: Replace the unchecked `len as u16` writes in these impls with checked
// conversions so oversized option payloads return a typed error instead of
// truncating on the wire.
pub(crate) trait WriteOptTo {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError>;
}

/// Write an option with its header and padding.
fn write_opt_with_header_pad<B: ByteOrder, W: Write>(
    writer: &mut W,
    code: u16,
    len: usize,
    content: impl FnOnce(&mut W) -> Result<(), std::io::Error>,
) -> Result<usize, PcapNgWriteError> {
    let pad_len = (4 - len % 4) % 4;

    let len: u16 = len
        .try_into()
        .map_err(|_| PcapNgWriteError::Validation { field: "Option length", source: ContentValidationError::OptionTooBig(len) })?;

    writer.write_u16::<B>(code)?;
    writer.write_u16::<B>(len as u16)?;
    content(writer)?;
    writer.write_all(&[0_u8; 3][..pad_len])?;

    Ok(len as usize + pad_len + 4)
}

impl<'a> WriteOptTo for Cow<'a, [u8]> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_pad::<B, _>(writer, code, self.len(), |w| w.write_all(self))
    }
}

impl<'a> WriteOptTo for Cow<'a, str> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_pad::<B, _>(writer, code, self.len(), |w| w.write_all(self.as_bytes()))
    }
}

impl WriteOptTo for u8 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_pad::<B, _>(writer, code, 1, |w| w.write_u8(*self))
    }
}

impl WriteOptTo for u16 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_pad::<B, _>(writer, code, 2, |w| w.write_u16::<B>(*self))
    }
}

impl WriteOptTo for u32 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_pad::<B, _>(writer, code, 4, |w| w.write_u32::<B>(*self))
    }
}

impl WriteOptTo for u64 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_pad::<B, _>(writer, code, 8, |w| w.write_u64::<B>(*self))
    }
}

impl WriteOptTo for i64 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_pad::<B, _>(writer, code, 8, |w| w.write_i64::<B>(*self))
    }
}

impl<'a> WriteOptTo for CommonOption<'a> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        match self {
            CommonOption::Comment(a) => write_opt_with_header_pad::<B, _>(writer, code, a.len(), |w| w.write_all(a.as_bytes())),
            CommonOption::CustomBinaryCopiable(a) => write_opt_with_header_pad::<B, _>(writer, code, a.value.len() + 4, |w| {
                w.write_u32::<B>(a.pen)?;
                w.write_all(&a.value)?;
                Ok(())
            }),
            CommonOption::CustomBinaryNonCopiable(a) => write_opt_with_header_pad::<B, _>(writer, code, a.value.len() + 4, |w| {
                w.write_u32::<B>(a.pen)?;
                w.write_all(&a.value)?;
                Ok(())
            }),
            CommonOption::CustomUtf8Copiable(a) => write_opt_with_header_pad::<B, _>(writer, code, a.value.len() + 4, |w| {
                w.write_u32::<B>(a.pen)?;
                w.write_all(&a.value.as_bytes())?;
                Ok(())
            }),
            CommonOption::CustomUtf8NonCopiable(a) => write_opt_with_header_pad::<B, _>(writer, code, a.value.len() + 4, |w| {
                w.write_u32::<B>(a.pen)?;
                w.write_all(&a.value.as_bytes())?;
                Ok(())
            }),
            CommonOption::Unknown(a) => write_opt_with_header_pad::<B, _>(writer, code, a.value.len(), |w| w.write_all(&a.value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use byteorder_slice::BigEndian;

    use crate::pcapng::PcapNgState;
    use crate::pcapng::blocks::opt_common::PcapNgOption;
    use crate::pcapng::errors::{OptionEntryError, PcapNgWriteError};

    #[derive(Debug, PartialEq)]
    struct PcapNgOptionImpl {}

    impl<'a> PcapNgOption<'a> for PcapNgOptionImpl {
        fn from_slice<B: byteorder_slice::ByteOrder>(
            _state: &PcapNgState,
            _interface_id: Option<u32>,
            _code: u16,
            _slice: &'a [u8],
        ) -> Result<Self, OptionEntryError>
        where
            Self: std::marker::Sized,
        {
            Ok(Self {})
        }

        fn write_to<B: byteorder_slice::ByteOrder, W: std::io::Write>(
            &self,
            _state: &PcapNgState,
            _interface_id: Option<u32>,
            _writer: &mut W,
        ) -> Result<usize, PcapNgWriteError> {
            Ok(0)
        }

        fn code_name(_code: u16) -> &'static str {
            "Option"
        }
    }

    /// Test that a list of option without an endofopt can be parsed
    #[test]
    fn opt_without_endofopt() {
        let data = [0, 1, 0, 4, 0, 0, 0, 0];
        let state = PcapNgState::default();

        let (rem, opts) = PcapNgOptionImpl::opts_from_slice::<BigEndian>(&state, None, &data).expect("Failed to read the options");

        assert_eq!(&opts, &[PcapNgOptionImpl {}]);
        assert!(rem.is_empty());
    }
}
