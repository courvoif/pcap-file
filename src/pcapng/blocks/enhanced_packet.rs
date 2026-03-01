//! Enhanced Packet Block (EPB).

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOptTo};
use crate::errors::PcapNgError;
use crate::pcapng::PcapNgState;

/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
#[derive(Clone, Debug, Default, IntoOwned, Eq, PartialEq)]
pub struct EnhancedPacketBlock<'a> {
    /// It specifies the interface this packet comes from.
    ///
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number of this field.
    pub interface_id: u32,

    /// Time elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: Duration,

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<EnhancedPacketOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for EnhancedPacketBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapNgError> {
        if slice.len() < 20 {
            return Err(PcapNgError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = slice.read_u32::<B>().unwrap();

        let timestamp = state.decode_timestamp::<B>(interface_id, &mut slice)?;

        let captured_len = slice.read_u32::<B>().unwrap();
        let original_len = slice.read_u32::<B>().unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapNgError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = EnhancedPacketOption::opts_from_slice::<B>(state, Some(interface_id), slice)?;
        let block = EnhancedPacketBlock { interface_id, timestamp, original_len, data: Cow::Borrowed(data), options };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgError> {
        let pad_len = (4 - (&self.data.len() % 4)) % 4;

        writer.write_u32::<B>(self.interface_id)?;

        state.encode_timestamp::<B, W>(self.interface_id, self.timestamp, writer)?;

        writer.write_u32::<B>(self.data.len() as u32)?;
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len = EnhancedPacketOption::write_opts_to::<B, W>(&self.options, state, Some(self.interface_id), writer)?;

        Ok(20 + &self.data.len() + pad_len + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::EnhancedPacket(self)
    }
}

/* ----- */

/// The Enhanced Packet Block (EPB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum EnhancedPacketOption<'a> {
    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// 64-bit integer value specifying the number of packets lost
    /// (by the interface and the operating system) between this packet and the preceding one for
    /// the same interface or, for the first packet for an interface, between this packet
    /// and the start of the capture process.
    DropCount(u64),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl<'a> PcapNgOption<'a> for EnhancedPacketOption<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        mut slice: &'a [u8],
    ) -> Result<Self, PcapNgError> {
        let opt = match code {
            2 => {
                if slice.len() != 4 {
                    return Err(PcapNgError::InvalidField("EnhancedPacketOption: Flags length != 4"));
                }
                EnhancedPacketOption::Flags(slice.read_u32::<B>().map_err(|_| PcapNgError::IncompleteBuffer(4, slice.len()))?)
            },
            3 => EnhancedPacketOption::Hash(Cow::Borrowed(slice)),
            4 => {
                if slice.len() != 8 {
                    return Err(PcapNgError::InvalidField("EnhancedPacketOption: DropCount length != 8"));
                }
                EnhancedPacketOption::DropCount(slice.read_u64::<B>().map_err(|_| PcapNgError::IncompleteBuffer(8, slice.len()))?)
            },
            _ => EnhancedPacketOption::Common(CommonOption::new::<B>(code, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, PcapNgError> {
        Ok(match self {
            EnhancedPacketOption::Flags(a) => a.write_opt_to::<B, W>(2, writer),
            EnhancedPacketOption::Hash(a) => a.write_opt_to::<B, W>(3, writer),
            EnhancedPacketOption::DropCount(a) => a.write_opt_to::<B, W>(4, writer),
            EnhancedPacketOption::Common(a) => a.write_opt_to::<B, W>(a.code(), writer),
        }?)
    }
}
