//! Generic block option types.

use std::borrow::Cow;
use std::io::{Result as IoResult, Write};

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use crate::errors::PcapError;
use crate::pcapng::PcapNgState;


/// Common fonctions of the PcapNg options
pub(crate) trait PcapNgOption<'a> {
    /// Parse an option from a slice
    fn from_slice<B: ByteOrder>(
        state: &PcapNgState,
        interface_id: Option<u32>,
        code: u16,
        length: u16,
        slice: &'a [u8],
    ) -> Result<Self, PcapError>
    where
        Self: std::marker::Sized;

    /// Parse all options in a block
    fn opts_from_slice<B: ByteOrder>(
        state: &PcapNgState,
        interface_id: Option<u32>,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Vec<Self>), PcapError>
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
                return Err(PcapError::InvalidField("Option: slice.len() < 4"));
            }

            let code = slice.read_u16::<B>().unwrap();
            let length = slice.read_u16::<B>().unwrap() as usize;
            let pad_len = (4 - (length % 4)) % 4;

            if code == 0 {
                return Ok((slice, options));
            }

            if slice.len() < length + pad_len {
                return Err(PcapError::InvalidField("Option: length + pad.len() > slice.len()"));
            }

            let tmp_slice = &slice[..length];
            let opt = Self::from_slice::<B>(state, interface_id, code, length as u16, tmp_slice)?;

            // Jump over the padding
            slice = &slice[length + pad_len..];

            options.push(opt);
        }

        Ok((slice, options))
    }

    /// Write the option to a writer
    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, interface_id: Option<u32>, writer: &mut W) -> Result<usize, PcapError>;

    /// Write all options in a block
    fn write_opts_to<B: ByteOrder, W: Write>(
        opts: &[Self],
        state: &PcapNgState,
        interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, PcapError>
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
    /// Option length
    pub length: u16,
    /// Option value
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownOption<'a> {
    /// Creates a new [`UnknownOption`]
    pub fn new(code: u16, length: u16, value: &'a [u8]) -> Self {
        UnknownOption { code, length, value: Cow::Borrowed(value) }
    }
}

/// Custom binary option
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct CustomBinaryOption<'a> {
    /// Option code
    pub code: u16,
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, [u8]>,
}

impl<'a> CustomBinaryOption<'a> {
    /// Parse an [`CustomBinaryOption`] from a slice
    pub fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<Self, PcapError> {
        let pen = src.read_u32::<B>().map_err(|_| PcapError::IncompleteBuffer)?;
        let opt = CustomBinaryOption { code, pen, value: Cow::Borrowed(src) };
        Ok(opt)
    }
}

/// Custom string (UTF-8) option
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct CustomUtf8Option<'a> {
    /// Option code
    pub code: u16,
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, str>,
}

impl<'a> CustomUtf8Option<'a> {
    /// Parse a [`CustomUtf8Option`] from a slice
    pub fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<Self, PcapError> {
        let pen = src.read_u32::<B>().map_err(|_| PcapError::IncompleteBuffer)?;
        let opt = CustomUtf8Option { code, pen, value: Cow::Borrowed(std::str::from_utf8(src)?) };
        Ok(opt)
    }
}

pub(crate) trait WriteOptTo {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize>;
}

impl<'a> WriteOptTo for Cow<'a, [u8]> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = self.len();
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_all(self)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

impl<'a> WriteOptTo for Cow<'a, str> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = self.len();
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_all(self.as_bytes())?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

impl WriteOptTo for u8 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(1)?;
        writer.write_u8(*self)?;
        writer.write_all(&[0_u8; 3])?;

        Ok(8)
    }
}

impl WriteOptTo for u16 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(2)?;
        writer.write_u16::<B>(*self)?;
        writer.write_all(&[0_u8; 2])?;

        Ok(8)
    }
}

impl WriteOptTo for u32 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(4)?;
        writer.write_u32::<B>(*self)?;

        Ok(8)
    }
}

impl WriteOptTo for u64 {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(8)?;
        writer.write_u64::<B>(*self)?;

        Ok(12)
    }
}

impl<'a> WriteOptTo for CustomBinaryOption<'a> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = &self.value.len() + 4;
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_u32::<B>(self.pen)?;
        writer.write_all(&self.value)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

impl<'a> WriteOptTo for CustomUtf8Option<'a> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = &self.value.len() + 4;
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_u32::<B>(self.pen)?;
        writer.write_all(self.value.as_bytes())?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

impl<'a> WriteOptTo for UnknownOption<'a> {
    fn write_opt_to<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = self.value.len();
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_all(&self.value)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

#[cfg(test)]
mod tests {
    use byteorder_slice::BigEndian;

    use crate::PcapError;
    use crate::pcapng::PcapNgState;
    use crate::pcapng::blocks::opt_common::PcapNgOption;

    #[derive(Debug, PartialEq)]
    struct PcapNgOptionImpl {}

    impl<'a> PcapNgOption<'a> for PcapNgOptionImpl {
        fn from_slice<B: byteorder_slice::ByteOrder>(
            _state: &PcapNgState,
            _interface_id: Option<u32>,
            _code: u16,
            _length: u16,
            _slice: &'a [u8],
        ) -> Result<Self, PcapError>
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
        ) -> Result<usize, PcapError> {
            Ok(0)
        }
    }


    /// Test that a list of option without an endofopt can be parsed
    #[test]
    fn opt_without_endofopt() {
        let data = [0, 1, 0, 4, 0, 0, 0, 0];
        let state = PcapNgState::default();

        let (rem, opts) = PcapNgOptionImpl::opts_from_slice::<BigEndian>(&state, None, &data).expect("Failed to read the options");

        assert_eq!(&opts, &[PcapNgOptionImpl {}]);
        assert_eq!(&rem, &[]);
    }
}
