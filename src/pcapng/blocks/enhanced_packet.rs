use crate::pcapng::blocks::opts_from_slice;
use crate::errors::PcapError;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::pcapng::{CustomUtf8Option, CustomBinaryOption, UnknownOption};


/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
#[derive(Clone, Debug)]
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
    pub data: &'a [u8],

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
            data,
            options
        };

        Ok((slice, block))
    }
}

#[derive(Clone, Debug)]
pub enum EnhancedPacketOption<'a> {

    /// Comment associated with the current block
    Comment(&'a str),

    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(&'a [u8]),

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

                1 => EnhancedPacketOption::Comment(std::str::from_utf8(slice)?),
                2 => {
                    if slice.len() != 4 {
                        return Err(PcapError::InvalidField("EnhancedPacketOption: Flags length != 4"))
                    }
                    EnhancedPacketOption::Flags(slice.read_u32::<B>()?)
                },
                3 => EnhancedPacketOption::Hash(slice),
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
}


