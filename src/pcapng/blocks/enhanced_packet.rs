use crate::pcapng::blocks::{Block, opts_from_slice};
use crate::errors::PcapError;
use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, BigEndian, LittleEndian};
use crate::pcapng::{CustomUtf8Option, CustomBinaryOption, UnknownOption, BlockType};
use std::borrow::Cow;
use derive_into_owned::IntoOwned;
use crate::Endianness;
use std::io::Write;
use std::io::Result as IoResult;

/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
#[derive(Clone, Debug, IntoOwned)]
pub struct EnhancedPacketBlock<'a> {

    /// It specifies the interface this packet comes from.
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number of this field.
    pub interface_id: u32,

    /// The timestamp is a single 64-bit unsigned integer that represents the number of units of time
    /// that have elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: u64,

    /// Number of octets captured from the packet (i.e. the length of the Packet Data field).
    pub captured_len: u32,

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<EnhancedPacketOption<'a>>
}

impl<'a> EnhancedPacketBlock<'a> {

    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {

        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = slice.read_u32::<B>()?;
        let timestamp = slice.read_u64::<B>()?;
        let captured_len = slice.read_u32::<B>()?;
        let original_len = slice.read_u32::<B>()?;

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = EnhancedPacketOption::from_slice::<B>(slice)?;
        let block = EnhancedPacketBlock {
            interface_id,
            timestamp,
            captured_len,
            original_len,
            data: Cow::Borrowed(data),
            options
        };

        Ok((slice, block))
    }

    pub fn write_to<B:ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {


        self.write_packet_to::<BigEndian>(body);
        self.write_opts_to::<BigEndian>(body);



        let len = block.body.len() as u32;
        block.initial_len = len;
        block.trailer_len = len;

        block
    }

    fn write_packet_to<B:ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];
        let pad_len = (4 - (self.captured_len as usize % 4)) % 4;

        writer.write_u32::<BigEndian>(self.interface_id)?;
        writer.write_u64::<BigEndian>(self.timestamp)?;
        writer.write_u32::<BigEndian>(self.captured_len)?;
        writer.write_u32::<BigEndian>(self.original_len)?;
        writer.write(data)?;
        writer.write(&pad[..pad_len])?;

        Ok(20 + data.len() + pad_len)
    }

    fn write_opts_to<B:ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        let mut have_opt = false;
        let mut written = 0;
        for opt in &self.options {
            written += opt.write_to::<B>(writer)?;
            have_opt = true;
        }

        if have_opt {
            writer.write_u16(0)?;
            writer.write_u16(0)?;
            written += 4;
        }

        Ok(written)
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub enum EnhancedPacketOption<'a> {

    /// Comment associated with the current block
    Comment(Cow<'a, str>),

    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// 64-bit integer value specifying the number of packets lost
    /// (by the interface and the operating system) between this packet and the preceding one for
    /// the same interface or, for the first packet for an interface, between this packet
    /// and the start of the capture process.
    DropCount(u64),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>)
}


impl<'a> EnhancedPacketOption<'a> {

    pub fn from_slice<B:ByteOrder>(slice: &'a [u8]) -> Result<(&'a[u8], Vec<Self>), PcapError> {

        opts_from_slice::<B, _, _>(slice, |mut slice, code, length| {

            let opt = match code {

                1 => EnhancedPacketOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
                2 => {
                    if slice.len() != 4 {
                        return Err(PcapError::InvalidField("EnhancedPacketOption: Flags length != 4"))
                    }
                    EnhancedPacketOption::Flags(slice.read_u32::<B>()?)
                },
                3 => EnhancedPacketOption::Hash(Cow::Borrowed(slice)),
                4 => {
                    if slice.len() != 8 {
                        return Err(PcapError::InvalidField("EnhancedPacketOption: DropCount length != 8"))
                    }
                    EnhancedPacketOption::DropCount(slice.read_u64::<B>()?)
                },

                2988 | 19372 => EnhancedPacketOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
                2989 | 19373 => EnhancedPacketOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

                _ => EnhancedPacketOption::Unknown(UnknownOption::new(code, length, slice))
            };

            Ok(opt)
        })
    }

    pub fn write_to<B:ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        let pad = [0_u8; 3];

        match self {

            EnhancedPacketOption::Comment(s) => {

                let len = s.as_bytes().len();
                let pad_len = (4-len%4)%4;

                writer.write_u16::<B>(1)?;
                writer.write_u16::<B>(len as u16)?;
                writer.write(s.as_bytes())?;
                writer.write(&pad[..pad_len])?;

                Ok(len + pad_len + 4)
            },
            EnhancedPacketOption::Flags(f) => {

                writer.write_u16::<B>(2)?;
                writer.write_u16::<B>(4)?;
                writer.write_u32::<B>(*f)?;

                Ok(8)
            },
            EnhancedPacketOption::Hash(h) => {

                let len = h.len();
                let pad_len = (4-len%4)%4;

                //Code
                writer.write_u16::<B>(3)?;
                //Len
                writer.write_u16::<B>(len as u16)?;
                //Hash
                writer.write(h)?;
                //Pad
                writer.write(&pad[..pad_len])?;

                Ok(len + pad_len + 4)
            },
            EnhancedPacketOption::DropCount(d) => {

                //Code
                writer.write_u16::<B>(4)?;
                //Len
                writer.write_u16::<B>(8)?;
                //Hash
                writer.write_u64::<B>(*d)?;

                Ok(12)
            },
            EnhancedPacketOption::CustomUtf8(c) => {
                c.write_to(writer)
            },
            EnhancedPacketOption::CustomBinary(c) => c.write_to(writer),
            EnhancedPacketOption::Unknown(u) => u.write_to(writer),
        }
    }
}
