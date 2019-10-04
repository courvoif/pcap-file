use crate::pcapng::blocks::{opts_from_slice, read_to_string, read_to_vec};
use crate::errors::PcapError;
use crate::DataLink;
use std::io::Read;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::peek_reader::PeekReader;
use std::borrow::Cow;


/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
pub struct EnhancedPacketBlock<'a> {

    /// It specifies the interface this packet comes from.
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number of this field.
    interface_id: u32,

    /// The timestamp is a single 64-bit unsigned integer that represents the number of units of time
    /// that have elapsed since 1970-01-01 00:00:00 UTC.
    timestamp: u64,

    /// Number of octets captured from the packet (i.e. the length of the Packet Data field).
    captured_len: u32,

    /// Actual length of the packet when it was transmitted on the network.
    original_len: u32,

    /// The data coming from the network, including link-layer headers.
    data:&'a [u8],

    /// Options
    options: Vec<EnhancedPacketOption<'a>>
}

impl<'a> EnhancedPacketBlock<'a> {

    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(Self, &'a [u8]), PcapError> {

        if slice.len() < 20 {
            return Err(PcapError::IncompleteBuffer(20 - slice.len()));
        }

        let interface_id = slice.read_u32::<B>()?;
        let timestamp = slice.read_u64::<B>()?;
        let captured_len = slice.read_u32::<B>()?;
        let original_len = slice.read_u32::<B>()?;

        let pad_len = (4 - captured_len as usize % 4) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::IncompleteBuffer(tot_len - slice.len()));
        }

        let mut data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (options, slice) = EnhancedPacketOption::from_slice::<B>(slice)?;
        let block = EnhancedPacketBlock {
            interface_id,
            timestamp,
            captured_len,
            original_len,
            data,
            options
        };

        Ok((block, slice))
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
    DropCount(u64)
}


impl<'a> EnhancedPacketOption<'a> {

    pub fn from_slice<B:ByteOrder>(slice: &'a [u8]) -> Result<(Vec<Self>, &'a[u8]), PcapError> {

        opts_from_slice::<B, _, _>(slice, |mut slice, type_, len| {

            let opt = match type_ {

                1 => EnhancedPacketOption::Comment(std::str::from_utf8(slice)?),
                2 => EnhancedPacketOption::Flags(slice.read_u32::<B>()?),
                3 => EnhancedPacketOption::Hash(slice),
                4 => EnhancedPacketOption::DropCount(slice.read_u64::<B>()?),

                _ => return Err(PcapError::InvalidField("EnhancedPacketOption type invalid"))
            };

            Ok(opt)
        })
    }
}


