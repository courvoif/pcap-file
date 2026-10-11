//! Generic block option types.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;
use std::num::NonZeroU16;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use crate::pcapng::PcapNgState;
use crate::pcapng::blocks::custom::{CustomBinaryOption, CustomUtf8Option};
use crate::pcapng::errors::{OptionEntryError, OptionError, WriteError};

/* ----- Option codes ----- */

/// Comment option code.
pub const COMMENT: u16 = 0x0001;
/// Copiable custom UTF-8 option code.
pub const CUSTOM_UTF8_OPTION_COPIABLE: u16 = 0x0BAC;
/// Non-copiable custom UTF-8 option code.
pub const CUSTOM_UTF8_OPTION_NON_COPIABLE: u16 = 0x4BAC;
/// Copiable custom binary option code.
pub const CUSTOM_BINARY_OPTION_COPIABLE: u16 = 0x0BAD;
/// Non-copiable custom binary option code.
pub const CUSTOM_BINARY_OPTION_NON_COPIABLE: u16 = 0x4BAD;

/* ----- Option length checks ----- */

/// Checks that an option value has exactly the expected byte length.
///
/// # Errors
///
/// Returns the expected and actual lengths when they differ.
pub(crate) fn check_opt_len(slice: &[u8], expected: usize) -> Result<(), OptionEntryError> {
    if slice.len() != expected {
        return Err(OptionEntryError::WrongSize {
            expected,
            actual: slice.len(),
        });
    }

    Ok(())
}

/* ----- Option lists ----- */

/// Parses all framed options in a block body.
pub(crate) fn opts_from_slice<'a, B: ByteOrder, O: PcapNgOption<'a>>(
    state: &PcapNgState,
    interface_id: Option<u32>,
    mut slice: &'a [u8],
) -> Result<(&'a [u8], Vec<O>), OptionError> {
    let mut options = vec![];

    while !slice.is_empty() {
        let (rem, raw_option) = RawOption::from_slice::<B>(slice).map_err(|source| {
            let code = if slice.len() >= 2 {
                let mut prefix = slice;
                prefix.read_u16::<B>().expect("slice length checked above")
            } else {
                0
            };
            let name = if slice.len() < 2 {
                "Option"
            } else if code == 0 {
                "End of Options"
            } else {
                O::name(code)
            };

            OptionError::new(code, name, source)
        })?;
        let code = raw_option.code;
        let value = raw_option.value;

        if code == 0 {
            raw_option
                .validate()
                .map_err(|source| OptionError::new(code, "End of Options", source))?;
            return Ok((rem, options));
        }

        let option = O::from_content::<B>(state, interface_id, code, value)
            .map_err(|source| OptionError::new(code, O::name(code), source))?;
        option
            .validate(state, interface_id)
            .map_err(|source| OptionError::new(code, O::name(code), source))?;

        options.push(option);
        slice = rem;
    }

    Ok((slice, options))
}

/// Validates and writes a nonempty option list followed by its end-of-options entry.
/// An empty list writes no bytes, including no terminator.
pub(crate) fn write_opts_to<'a, B: ByteOrder, O: PcapNgOption<'a>, W: Write>(
    options: &[O],
    state: &PcapNgState,
    interface_id: Option<u32>,
    writer: &mut W,
) -> Result<usize, WriteError<OptionError>> {
    validate_opts(options, state, interface_id).map_err(WriteError::Other)?;

    let mut written = 0;

    for option in options {
        written += option.write_to::<B, W>(state, interface_id, writer).map_err(|error| {
            error.map_other(|source| {
                let code = option.code();
                OptionError::new(code, O::name(code), source)
            })
        })?;
    }

    if !options.is_empty() {
        written += RawOption::write_framed_to::<B, _, _>(writer, 0, 0, |_| Ok(()))
            .map_err(|error| error.map_other(|source| OptionError::new(0, "End of Options", source)))?;
    }

    Ok(written)
}

/* ----- Option validation ----- */

/// Validates each option against the supplied pcapng state.
pub(crate) fn validate_opts<'a, O: PcapNgOption<'a>>(
    options: &[O],
    state: &PcapNgState,
    interface_id: Option<u32>,
) -> Result<(), OptionError> {
    for option in options {
        option.validate(state, interface_id).map_err(|source| {
            let code = option.code();
            OptionError::new(code, O::name(code), source)
        })?;
    }

    Ok(())
}

/// Checks that selected singleton options occur at most once in a block.
/// Select only known singleton variants so repeatable and unknown options are preserved.
///
/// # Errors
///
/// Remove repeated singleton options before validating the block again.
pub(crate) fn validate_unique_opts<'a, O: PcapNgOption<'a>>(
    options: &[O],
    must_be_unique: impl Fn(&O) -> bool,
) -> Result<(), OptionError> {
    let mut seen = Vec::new();

    for option in options {
        if !must_be_unique(option) {
            continue;
        }

        let code = option.code();
        if seen.contains(&code) {
            return Err(OptionError::new(code, O::name(code), OptionEntryError::Duplicate));
        }

        seen.push(code);
    }

    Ok(())
}

/* ----- Common options ----- */

/// Common pcapng block options.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum CommonOption<'a> {
    /// Comment.
    Comment(Cow<'a, str>),

    /// Custom option containing copiable bytes in the Custom Data portion.
    CustomBinaryCopiable(CustomBinaryOption<'a, true>),

    /// Custom option containing non-copiable bytes in the Custom Data portion.
    CustomBinaryNonCopiable(CustomBinaryOption<'a, false>),

    /// Custom option containing a copiable UTF-8 string in the Custom Data portion.
    CustomUtf8Copiable(CustomUtf8Option<'a, true>),

    /// Custom option containing a non-copiable UTF-8 string in the Custom Data portion.
    CustomUtf8NonCopiable(CustomUtf8Option<'a, false>),

    /// Unknown option.
    Unknown(UnknownOption<'a>),
}

impl<'a> CommonOption<'a> {
    /// Returns the encoded option code.
    pub(crate) fn code(&self) -> u16 {
        match self {
            Self::Comment(_) => COMMENT,
            Self::CustomBinaryCopiable(_) => CUSTOM_BINARY_OPTION_COPIABLE,
            Self::CustomBinaryNonCopiable(_) => CUSTOM_BINARY_OPTION_NON_COPIABLE,
            Self::CustomUtf8Copiable(_) => CUSTOM_UTF8_OPTION_COPIABLE,
            Self::CustomUtf8NonCopiable(_) => CUSTOM_UTF8_OPTION_NON_COPIABLE,
            Self::Unknown(option) => option.code.get(),
        }
    }

    /// Decodes a common option value by code.
    pub(crate) fn from_content<B: ByteOrder>(code: u16, slice: &'a [u8]) -> Result<Self, OptionEntryError> {
        Ok(match code {
            COMMENT => CommonOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            CUSTOM_UTF8_OPTION_COPIABLE => CommonOption::CustomUtf8Copiable(CustomUtf8Option::from_slice::<B>(slice)?),
            CUSTOM_UTF8_OPTION_NON_COPIABLE => {
                CommonOption::CustomUtf8NonCopiable(CustomUtf8Option::from_slice::<B>(slice)?)
            }
            CUSTOM_BINARY_OPTION_COPIABLE => {
                CommonOption::CustomBinaryCopiable(CustomBinaryOption::from_slice::<B>(slice)?)
            }
            CUSTOM_BINARY_OPTION_NON_COPIABLE => {
                CommonOption::CustomBinaryNonCopiable(CustomBinaryOption::from_slice::<B>(slice)?)
            }
            _ => CommonOption::Unknown(UnknownOption::new(code, slice)?),
        })
    }

    /// Returns the common option name for a code.
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

    /// Writes a common option with its code and padding.
    pub(crate) fn write_to<B: ByteOrder, W: Write>(
        &self,
        writer: &mut W,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        match self {
            CommonOption::Comment(value) => write_bytes_option::<B, _>(writer, COMMENT, value.as_bytes()),
            CommonOption::CustomBinaryCopiable(option) => {
                write_custom_option::<B, _>(writer, CUSTOM_BINARY_OPTION_COPIABLE, option.pen, &option.value)
            }
            CommonOption::CustomBinaryNonCopiable(option) => {
                write_custom_option::<B, _>(writer, CUSTOM_BINARY_OPTION_NON_COPIABLE, option.pen, &option.value)
            }
            CommonOption::CustomUtf8Copiable(option) => {
                write_custom_option::<B, _>(writer, CUSTOM_UTF8_OPTION_COPIABLE, option.pen, option.value.as_bytes())
            }
            CommonOption::CustomUtf8NonCopiable(option) => write_custom_option::<B, _>(
                writer,
                CUSTOM_UTF8_OPTION_NON_COPIABLE,
                option.pen,
                option.value.as_bytes(),
            ),
            CommonOption::Unknown(option) => write_bytes_option::<B, _>(writer, option.code.get(), &option.value),
        }
    }
}

/* ----- Raw options ----- */

/// Raw pcapng option with its framing fields and unparsed value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawOption<'a> {
    /// Numeric option code.
    pub code: u16,
    /// Unparsed option value.
    pub value: &'a [u8],
}

impl<'a> RawOption<'a> {
    /// Parses one raw option, including its header and padding, from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice does not contain the complete option frame.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), OptionEntryError> {
        if slice.len() < 4 {
            return Err(OptionEntryError::ContentTooSmall {
                needed: 4,
                actual: slice.len(),
            });
        }

        let code = slice.read_u16::<B>().expect("slice length checked above");
        let length = slice.read_u16::<B>().expect("slice length checked above");
        let value_len = length as usize;
        let pad_len = (4 - value_len % 4) % 4;

        if slice.len() < value_len + pad_len {
            return Err(OptionEntryError::ContentTooSmall {
                needed: value_len + pad_len,
                actual: slice.len(),
            });
        }

        let value = &slice[..value_len];
        let rem = &slice[value_len + pad_len..];

        Ok((rem, Self { code, value }))
    }

    /// Validates constraints imposed by the option framing itself.
    pub fn validate(&self) -> Result<(), OptionEntryError> {
        if self.code == 0 {
            check_opt_len(self.value, 0)?;
        }

        Ok(())
    }

    /// Writes one raw option with its header and padding.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is too large or the writer fails.
    pub(crate) fn write_framed_to<B, W, F>(
        writer: &mut W,
        code: u16,
        content_len: usize,
        write_content: F,
    ) -> Result<usize, WriteError<OptionEntryError>>
    where
        B: ByteOrder,
        W: Write,
        F: FnOnce(&mut W) -> std::io::Result<()>,
    {
        let content_len_u16 = content_len.try_into().map_err(|_| {
            WriteError::Other(OptionEntryError::TooLarge {
                actual: content_len,
                maximum: u16::MAX as usize,
            })
        })?;

        let pad_len = (4 - (content_len % 4)) % 4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(content_len_u16)?;
        write_content(writer)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(4 + content_len + pad_len)
    }
}

/* ----- Helpers for writing option values ----- */

/// Writes bytes as a framed option.
pub(crate) fn write_bytes_option<B: ByteOrder, W: Write>(
    writer: &mut W,
    code: u16,
    value: &[u8],
) -> Result<usize, WriteError<OptionEntryError>> {
    RawOption::write_framed_to::<B, _, _>(writer, code, value.len(), |writer| {
        writer.write_all(value)?;
        Ok(())
    })
}

/// Writes an 8-bit value as a framed option.
pub(crate) fn write_u8_option<B: ByteOrder, W: Write>(
    writer: &mut W,
    code: u16,
    value: u8,
) -> Result<usize, WriteError<OptionEntryError>> {
    RawOption::write_framed_to::<B, _, _>(writer, code, 1, |writer| writer.write_u8(value))
}

/// Writes a 32-bit value as a framed option.
pub(crate) fn write_u32_option<B: ByteOrder, W: Write>(
    writer: &mut W,
    code: u16,
    value: u32,
) -> Result<usize, WriteError<OptionEntryError>> {
    RawOption::write_framed_to::<B, _, _>(writer, code, 4, |writer| writer.write_u32::<B>(value))
}

/// Writes a 64-bit value as a framed option.
pub(crate) fn write_u64_option<B: ByteOrder, W: Write>(
    writer: &mut W,
    code: u16,
    value: u64,
) -> Result<usize, WriteError<OptionEntryError>> {
    RawOption::write_framed_to::<B, _, _>(writer, code, 8, |writer| writer.write_u64::<B>(value))
}

/// Writes a signed 64-bit value as a framed option.
pub(crate) fn write_i64_option<B: ByteOrder, W: Write>(
    writer: &mut W,
    code: u16,
    value: i64,
) -> Result<usize, WriteError<OptionEntryError>> {
    RawOption::write_framed_to::<B, _, _>(writer, code, 8, |writer| writer.write_i64::<B>(value))
}

/// Writes a custom value with its private enterprise number.
fn write_custom_option<B: ByteOrder, W: Write>(
    writer: &mut W,
    code: u16,
    pen: u32,
    value: &[u8],
) -> Result<usize, WriteError<OptionEntryError>> {
    RawOption::write_framed_to::<B, _, _>(writer, code, value.len() + 4, |writer| {
        writer.write_u32::<B>(pen)?;
        writer.write_all(value)?;
        Ok(())
    })
}

/* ----- Option interface ----- */

/// Common behavior for pcapng options.
pub(crate) trait PcapNgOption<'a> {
    /// Parses an option from a byte slice without semantic validation.
    /// [`opts_from_slice`] validates the returned option immediately after
    /// this call.
    fn from_content<B: ByteOrder>(
        state: &PcapNgState,
        interface_id: Option<u32>,
        code: u16,
        slice: &'a [u8],
    ) -> Result<Self, OptionEntryError>
    where
        Self: std::marker::Sized;

    /// Writes an already validated option to a writer.
    /// [`write_opts_to`] validates the option list before calling this method.
    fn write_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, WriteError<OptionEntryError>>;

    /// Validates the decoded option against the supplied pcapng state.
    fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError>;

    /// Returns the encoded option code.
    fn code(&self) -> u16;

    /// Returns the option name for a code.
    fn name(code: u16) -> &'static str;
}

/* ----- Unknown options ----- */

/// Unknown option.
///
/// Stores an option whose code is not recognized.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownOption<'a> {
    /// Option code, excluding the end-of-options marker.
    pub code: NonZeroU16,
    /// Option value.
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownOption<'a> {
    /// Creates an unknown option with a nonzero code.
    ///
    /// # Errors
    ///
    /// Use a nonzero code because code `0` is reserved for the end-of-options marker.
    pub fn new(code: u16, value: &'a [u8]) -> Result<Self, OptionEntryError> {
        let code = NonZeroU16::new(code).ok_or(OptionEntryError::InvalidCode(code))?;

        Ok(UnknownOption {
            code,
            value: Cow::Borrowed(value),
        })
    }
}

/* ----- Packet hashes ----- */

/// Packet hash value shared by Enhanced Packet and Packet Block options.
/// Digests retain their byte order regardless of the section's endianness.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum PacketHash<'a> {
    /// CRC32 digest (algorithm `2`).
    Crc32([u8; 4]),
    /// MD5 digest (algorithm `3`).
    Md5([u8; 16]),
    /// SHA-1 digest (algorithm `4`).
    Sha1([u8; 20]),
    /// Toeplitz digest (algorithm `5`).
    Toeplitz([u8; 4]),
    /// Preserved hash for an unsupported algorithm, including codes `0` and `1`.
    /// Algorithm codes and digest lengths are not validated for this variant.
    Unknown {
        /// Algorithm identifier from the first byte of the option value.
        algorithm: u8,
        /// Digest bytes following the algorithm identifier.
        value: Cow<'a, [u8]>,
    },
}

impl<'a> PacketHash<'a> {
    /// Parses an algorithm byte and digest from a hash option value.
    /// Unsupported algorithms retain their digest as a borrowed slice.
    ///
    /// # Errors
    ///
    /// Supply an algorithm byte and the exact digest length for a supported algorithm.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, OptionEntryError> {
        let (&algorithm, value) = slice
            .split_first()
            .ok_or(OptionEntryError::ContentTooSmall { needed: 1, actual: 0 })?;

        Ok(match algorithm {
            2 => {
                check_opt_len(slice, 5)?;
                Self::Crc32(value.try_into().expect("hash length checked above"))
            }
            3 => {
                check_opt_len(slice, 17)?;
                Self::Md5(value.try_into().expect("hash length checked above"))
            }
            4 => {
                check_opt_len(slice, 21)?;
                Self::Sha1(value.try_into().expect("hash length checked above"))
            }
            5 => {
                check_opt_len(slice, 5)?;
                Self::Toeplitz(value.try_into().expect("hash length checked above"))
            }
            _ => Self::Unknown {
                algorithm,
                value: Cow::Borrowed(value),
            },
        })
    }

    /// Writes the algorithm byte and digest as a framed hash option.
    pub(crate) fn write_to<B: ByteOrder, W: Write>(
        &self,
        writer: &mut W,
        code: u16,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        let (algorithm, value): (u8, &[u8]) = match self {
            Self::Crc32(value) => (2, value),
            Self::Md5(value) => (3, value),
            Self::Sha1(value) => (4, value),
            Self::Toeplitz(value) => (5, value),
            Self::Unknown { algorithm, value } => (*algorithm, value),
        };

        RawOption::write_framed_to::<B, _, _>(writer, code, value.len() + 1, |writer| {
            writer.write_u8(algorithm)?;
            writer.write_all(value)
        })
    }
}

/* ----- Tests ----- */

/// Checks option framing, parsing, and validation behavior.
#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use std::io::Write;

    use byteorder_slice::BigEndian;

    use crate::pcapng::PcapNgState;
    use crate::pcapng::blocks::opt_common::{PcapNgOption, RawOption, opts_from_slice, write_opts_to};
    use crate::pcapng::errors::{OptionEntryError, OptionError, WriteError};

    /// Minimal option type for list parsing.
    #[derive(Debug, PartialEq)]
    struct PcapNgOptionImpl {}

    /// Checks that raw options consume and write complete frames.
    #[test]
    fn raw_option_parses_and_writes_its_frame() {
        let data = [0, 2, 0, 1, 7, 0, 0, 0, 9];
        let (rem, option) = RawOption::from_slice::<BigEndian>(&data).unwrap();

        assert_eq!(rem, &[9]);
        assert_eq!(option.code, 2);
        assert_eq!(option.value, &[7]);
        option.validate().unwrap();

        let mut encoded = Vec::new();
        RawOption::write_framed_to::<BigEndian, _, _>(&mut encoded, option.code, option.value.len(), |writer| {
            writer.write_all(option.value)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(encoded, &data[..8]);
    }

    /// Checks that the end marker cannot carry a value.
    #[test]
    fn raw_end_option_rejects_a_value() {
        let option = RawOption { code: 0, value: &[1] };

        assert!(matches!(
            option.validate(),
            Err(OptionEntryError::WrongSize { expected: 0, actual: 1 })
        ));
    }

    impl<'a> PcapNgOption<'a> for PcapNgOptionImpl {
        /// Returns a dummy option for list framing checks.
        fn from_content<B: byteorder_slice::ByteOrder>(
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

        /// Returns zero written bytes without changing the output.
        fn write_to<B: byteorder_slice::ByteOrder, W: std::io::Write>(
            &self,
            _state: &PcapNgState,
            _interface_id: Option<u32>,
            _writer: &mut W,
        ) -> Result<usize, WriteError<OptionEntryError>> {
            Ok(0)
        }

        /// Accepts the dummy option without additional constraints.
        fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError> {
            Ok(())
        }

        /// Returns the comment code used by the framing fixture.
        fn code(&self) -> u16 {
            1
        }

        /// Returns the fixture option name.
        fn name(_code: u16) -> &'static str {
            "Option"
        }
    }

    /// Tests that an option list without an end-of-options marker can be parsed.
    #[test]
    fn opt_without_endofopt() {
        let data = [0, 1, 0, 4, 0, 0, 0, 0];
        let state = PcapNgState::default();

        let (rem, opts) =
            opts_from_slice::<BigEndian, PcapNgOptionImpl>(&state, None, &data).expect("Failed to read the options");

        assert_eq!(&opts, &[PcapNgOptionImpl {}]);
        assert!(rem.is_empty());
    }

    /// Option type with explicit validation for list writing.
    #[derive(Debug)]
    struct ValidatedOption {
        /// Whether validation succeeds.
        valid: bool,
    }

    impl<'a> PcapNgOption<'a> for ValidatedOption {
        /// Decodes an option value for the supplied option code.
        fn from_content<B: byteorder_slice::ByteOrder>(
            _state: &PcapNgState,
            _interface_id: Option<u32>,
            _code: u16,
            _slice: &'a [u8],
        ) -> Result<Self, OptionEntryError> {
            Ok(Self { valid: true })
        }

        /// Returns the option name for its code.
        fn name(_code: u16) -> &'static str {
            "ValidatedOption"
        }

        /// Returns the encoded option code.
        fn code(&self) -> u16 {
            1
        }

        /// Checks the constraints applicable to this value.
        fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError> {
            if self.valid {
                Ok(())
            } else {
                Err(OptionEntryError::ContentTooSmall { needed: 1, actual: 0 })
            }
        }

        /// Writes this value using the selected byte order.
        fn write_to<B: byteorder_slice::ByteOrder, W: std::io::Write>(
            &self,
            _state: &PcapNgState,
            _interface_id: Option<u32>,
            writer: &mut W,
        ) -> Result<usize, WriteError<OptionEntryError>> {
            RawOption::write_framed_to::<B, _, _>(writer, 1, 1, |writer| {
                writer.write_all(&[1])?;
                Ok(())
            })
        }
    }

    /// Checks the option list length and terminator.
    #[test]
    fn writes_options_and_end_marker_with_complete_length() {
        let options = [ValidatedOption { valid: true }];
        let mut encoded = Vec::new();

        let written =
            write_opts_to::<BigEndian, ValidatedOption, _>(&options, &PcapNgState::default(), None, &mut encoded)
                .unwrap();

        assert_eq!(written, encoded.len());
        assert_eq!(encoded, [0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]);
    }

    /// Checks that validation finishes before any option is written.
    #[test]
    fn validates_all_options_before_writing_any() {
        let options = [ValidatedOption { valid: true }, ValidatedOption { valid: false }];
        let mut encoded = Vec::new();

        let error =
            write_opts_to::<BigEndian, ValidatedOption, _>(&options, &PcapNgState::default(), None, &mut encoded)
                .unwrap_err();

        assert!(encoded.is_empty());
        assert!(matches!(
            error,
            WriteError::Other(OptionError { source, .. })
                if matches!(*source, OptionEntryError::ContentTooSmall { needed: 1, actual: 0 })
        ));
    }
}
