use crate::pcapng::blocks::opts_from_slice;
use crate::errors::PcapError;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::pcapng::{CustomUtf8Option, CustomBinaryOption, UnknownOption};
use std::borrow::Cow;
use derive_into_owned::IntoOwned;


/// The Packet Block is obsolete, and MUST NOT be used in new files.
/// Use the Enhanced Packet Block or Simple Packet Block instead.
#[derive(Clone, Debug, IntoOwned)]
pub struct PacketBlock<'a> {

    /// It specifies the interface this packet comes from.
    pub interface_id: u16,

    /// Local drop counter.
    /// It specifies the number of packets lost (by the interface and the operating system)
    /// between this packet and the preceding one.
    pub drop_count: u16,

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
    pub options: Vec<PacketOption<'a>>
}

impl<'a> PacketBlock<'a> {

    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {

        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = slice.read_u16::<B>()?;
        let drop_count = slice.read_u16::<B>()?;
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

        let (slice, options) = PacketOption::from_slice::<B>(slice)?;
        let block = PacketBlock {
            interface_id,
            drop_count,
            timestamp,
            captured_len,
            original_len,
            data: Cow::Borrowed(data),
            options
        };

        Ok((slice, block))
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub enum PacketOption<'a> {

    /// Comment associated with the current block
    Comment(Cow<'a, str>),

    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>)
}


impl<'a> PacketOption<'a> {

    pub fn from_slice<B:ByteOrder>(slice: &'a [u8]) -> Result<(&'a[u8], Vec<Self>), PcapError> {

        opts_from_slice::<B, _, _>(slice, |mut slice, code, length| {

            let opt = match code {

                1 => PacketOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
                2 => {
                    if slice.len() != 4 {
                        return Err(PcapError::InvalidField("PacketOption: Flags length != 4"))
                    }
                    PacketOption::Flags(slice.read_u32::<B>()?)
                },
                3 => PacketOption::Hash(Cow::Borrowed(slice)),

                2988 | 19372 => PacketOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
                2989 | 19373 => PacketOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

                _ => PacketOption::Unknown(UnknownOption::new(code, length, slice))
            };

            Ok(opt)
        })
    }
}


