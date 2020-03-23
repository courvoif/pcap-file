use byteorder::{ByteOrder, LittleEndian, BigEndian, ReadBytesExt};
use std::io::{Read, Write};
use crate::errors::PcapError;
use std::borrow::Cow;
use byteorder::WriteBytesExt;
use crate::pcapng::blocks::{SectionHeaderBlock, InterfaceDescriptionBlock, EnhancedPacketBlock, SimplePacketBlock, NameResolutionBlock, InterfaceStatisticsBlock, SystemdJournalExportBlock};
use crate::pcapng::PacketBlock;
use crate::Endianness;
use derive_into_owned::IntoOwned;


pub(crate) trait PcapNgOption {

    /// Parse all options in a block
    fn opts_from_slice<B: ByteOrder>(mut slice: &[u8]) -> Result<(&[u8], Vec<Self>), PcapError> {

        let mut options = vec![];

        // If there is nothing left in the slice, it means that there is no option
        if slice.is_empty() {
            return Ok((slice, options))
        }

        while !slice.is_empty() {

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
            let opt = Self::from_slice(code, length as u16, data: &[u8])?;

            // Jump over the padding
            slice = &slice[length+pad_len..];

            options.push(opt);
        }

        Err(PcapError::InvalidField("Invalid option"))
    }

    fn from_slice(code: u16, length: u16, slice: &[u8]) -> Result<Self, PcapError>;
    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize>;
}

#[derive(Clone, Debug, IntoOwned)]
pub struct UnknownOption<'a> {
    pub code: u16,
    pub length: u16,
    pub value: Cow<'a, [u8]>
}

impl<'a> UnknownOption<'a> {
    pub fn new(code: u16, length: u16, value: &'a[u8]) -> Self {
        UnknownOption {
            code,
            length,
            value: Cow::Borrowed(value)
        }
    }

    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];
        let len = &self.length;
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(self.code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write(&self.value)?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct CustomBinaryOption<'a> {
    pub code: u16,
    pub pen: u32,
    pub value: Cow<'a, [u8]>
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

    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];
        let len = &self.value.len() + 4;
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(self.code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_u32::<B>(self.pen)?;
        writer.write(&self.value)?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 8)
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct CustomUtf8Option<'a> {
    pub code: u16,
    pub pen: u32,
    pub value: Cow<'a, str>
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

    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];
        let len = &self.as_bytes().len() + 4;
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(self.code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_u32::<B>(self.pen)?;
        writer.write(&self.as_bytes())?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 8)
    }
}

pub(crate) trait WriteOptTo {
    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W);
}

impl<'a> WriteOptTo for Cow<'a, [u8]> {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        let len = b.len();
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write(b)?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

impl<'a> WriteOptTo for Cow<'a, str> {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        let len = s.as_bytes().len();
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write(s.as_bytes())?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 4)
    }
}

impl<'a> WriteOptTo for u8 {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(1)?;
        writer.write_u8(*d)?;
        wrier.write([0_u8;3])?;

        Ok(12)
    }
}

impl<'a> WriteOptTo for u16 {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(2)?;
        writer.write_u8(*d)?;
        wrier.write([0_u8;2])?;

        Ok(12)
    }
}

impl<'a> WriteOptTo for u32 {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(4)?;
        writer.write_u8(*d)?;

        Ok(12)
    }
}

impl<'a> WriteOptTo for u64 {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(8)?;
        writer.write_u64::<B>(*d)?;

        Ok(12)
    }
}

impl<'a> WriteOptTo for CustomBinaryOption {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];
        let len = &self.value.len() + 4;
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_u32::<B>(self.pen)?;
        writer.write(&self.value)?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 8)
    }
}

impl<'a> WriteOptTo for CustomUtf8Option {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];
        let len = &self.value.len() + 4;
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write_u32::<B>(self.pen)?;
        writer.write(&self.value.as_bytes())?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 8)
    }
}

impl<'a> WriteOptTo for UnknownOption {

    fn write_opt_to<B: ByteOrder, W: write>(&self, code: u16, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];
        let len = &self.value.len();
        let pad_len = (4-len%4)%4;

        writer.write_u16::<B>(code)?;
        writer.write_u16::<B>(len as u16)?;
        writer.write(&self.value)?;
        writer.write(&pad[..pad_len])?;

        Ok(len + pad_len + 4)
    }
}