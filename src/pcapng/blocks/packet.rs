//! Packet Block.

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::ByteOrder;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOptTo};
use crate::errors::PcapError;
use crate::pcapng::PcapNgState;

/// The Packet Block is obsolete, and MUST NOT be used in new files.
/// Use the Enhanced Packet Block or Simple Packet Block instead.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct PacketBlock<'a> {
    /// It specifies the interface this packet comes from.
    pub interface_id: u16,

    /// Local drop counter.
    /// 
    /// It specifies the number of packets lost (by the interface and the operating system)
    /// between this packet and the preceding one.
    pub drop_count: u16,

    /// Time elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: Duration,

    /// Number of octets captured from the packet (i.e. the length of the Packet Data field).
    pub captured_len: u32,

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<PacketOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for PacketBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = slice.read_u16::<B>().unwrap();
        let drop_count = slice.read_u16::<B>().unwrap();
        let timestamp = state.decode_timestamp::<B>(interface_id as u32, &mut slice)?;
        let captured_len = slice.read_u32::<B>().unwrap();
        let original_len = slice.read_u32::<B>().unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = PacketOption::opts_from_slice::<B>(state, Some(interface_id as u32), slice)?;
        let block = PacketBlock {
            interface_id,
            drop_count,
            timestamp,
            captured_len,
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapError> {
        writer.write_u16::<B>(self.interface_id)?;
        writer.write_u16::<B>(self.drop_count)?;
        state.encode_timestamp::<B, W>(self.interface_id as u32, self.timestamp, writer)?;
        writer.write_u32::<B>(self.captured_len)?;
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;

        let pad_len = (4 - (self.captured_len as usize % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len = PacketOption::write_opts_to::<B, _>(&self.options, state, Some(self.interface_id as u32), writer)?;

        Ok(20 + self.data.len() + pad_len + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::Packet(self)
    }
}

/// Packet Block option
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum PacketOption<'a> {
    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl<'a> PcapNgOption<'a> for PacketOption<'a> {
    fn from_slice<B: ByteOrder>(_state: &PcapNgState, _interface_id: Option<u32>, code: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            2 => {
                if slice.len() != 4 {
                    return Err(PcapError::InvalidField("PacketOption: Flags length != 4"));
                }
                PacketOption::Flags(slice.read_u32::<B>().map_err(|_| PcapError::IncompleteBuffer)?)
            },
            3 => PacketOption::Hash(Cow::Borrowed(slice)),
            _ => PacketOption::Common(CommonOption::new::<B>(code, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, _state: &PcapNgState, _interface_id: Option<u32>, writer: &mut W) -> Result<usize, PcapError> {
        Ok(match self {
            PacketOption::Flags(a) => a.write_opt_to::<B, W>(2, writer),
            PacketOption::Hash(a) => a.write_opt_to::<B, W>(3, writer),
            PacketOption::Common(a) => a.write_opt_to::<B, W>(a.code(), writer),
        }?)
    }
}
