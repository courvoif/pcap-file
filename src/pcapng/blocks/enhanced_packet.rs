//! Enhanced Packet Block (EPB).

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOptTo};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockContentParseError, OptionEntryError, PcapNgWriteError};

/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
#[derive(Clone, Debug, Default, IntoOwned, Eq, PartialEq)]
pub struct EnhancedPacketBlock<'a> {
    /// It specifies the interface this packet comes from.
    ///
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number of this field.
    pub interface_id: u32,

    /// Nanoseconds elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: i128,

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<EnhancedPacketOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for EnhancedPacketBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockContentParseError> {
        if slice.len() < 20 {
            return Err(BlockContentParseError::BlockContentTooSmall { needed: 20, actual: slice.len() });
        }

        let interface_id = slice.read_u32::<B>().expect("slice length checked above");
        let timestamp_high = slice.read_u32::<B>().expect("slice length checked above");
        let timestamp_low = slice.read_u32::<B>().expect("slice length checked above");
        let timestamp = state.decode_timestamp(interface_id, timestamp_high, timestamp_low)?;

        let captured_len = slice.read_u32::<B>().expect("slice length checked above");
        let original_len = slice.read_u32::<B>().expect("slice length checked above");

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(BlockContentParseError::BlockContentTooSmall { needed: tot_len, actual: slice.len() });
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = EnhancedPacketOption::opts_from_slice::<B>(state, Some(interface_id), slice)?;
        let block = EnhancedPacketBlock { interface_id, timestamp, original_len, data: Cow::Borrowed(data), options };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        let pad_len = (4 - (&self.data.len() % 4)) % 4;

        writer.write_u32::<B>(self.interface_id)?;
        let (timestamp_high, timestamp_low) = state
            .encode_timestamp(self.interface_id, self.timestamp)
            .map_err(|source| PcapNgWriteError::Validation { field: "EnhancedPacketBlock.timestamp", source })?;
        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;

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

impl EnhancedPacketOption<'_> {
    const FLAGS: u16 = 2;
    const HASH: u16 = 3;
    const DROP_COUNT: u16 = 4;
}

impl<'a> PcapNgOption<'a> for EnhancedPacketOption<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        mut slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::FLAGS => {
                if slice.len() != 4 {
                    return Err(OptionEntryError::WrongSize { expected: 4, actual: slice.len() });
                }
                EnhancedPacketOption::Flags(slice.read_u32::<B>().expect("slice length checked above"))
            },
            Self::HASH => EnhancedPacketOption::Hash(Cow::Borrowed(slice)),
            Self::DROP_COUNT => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                EnhancedPacketOption::DropCount(slice.read_u64::<B>().expect("slice length checked above"))
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
    ) -> Result<usize, PcapNgWriteError> {
        match self {
            EnhancedPacketOption::Flags(a) => a.write_opt_to::<B, W>(2, writer).map_err(Into::into),
            EnhancedPacketOption::Hash(a) => a.write_opt_to::<B, W>(3, writer).map_err(Into::into),
            EnhancedPacketOption::DropCount(a) => a.write_opt_to::<B, W>(4, writer).map_err(Into::into),
            EnhancedPacketOption::Common(a) => a.write_opt_to::<B, W>(a.code(), writer).map_err(Into::into),
        }
    }

    fn code_name(code: u16) -> &'static str {
        match code {
            Self::FLAGS => "Flags",
            Self::HASH => "Hash",
            Self::DROP_COUNT => "Drop Count",
            _ => CommonOption::code_name(code),
        }
    }
}
