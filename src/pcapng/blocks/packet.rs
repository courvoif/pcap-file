//! [`Packet Block`](PacketBlock).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock, checked_body_len};
use super::opt_common::{
    CommonOption, PacketHash, PcapNgOption, check_opt_len, opts_from_slice, validate_opts, validate_unique_opts,
    write_opts_to, write_u32_option,
};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, OptionEntryError, WriteError};

/* ----- PacketBlock ----- */

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

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<PacketOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for PacketBlock<'a> {
    /// Numeric type code of this block.
    const TYPE: u32 = 0x00000002;
    /// Human-readable name of this block.
    const NAME: &'static str = "Packet Block";

    /// Decodes this block body using the supplied section state.
    fn from_body<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError> {
        if slice.len() < 20 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 20,
                actual: slice.len(),
            });
        }

        let interface_id = slice.read_u16::<B>().unwrap();
        let drop_count = slice.read_u16::<B>().unwrap();
        let timestamp_high = slice.read_u32::<B>().unwrap();
        let timestamp_low = slice.read_u32::<B>().unwrap();
        let timestamp = state.decode_timestamp(interface_id as u32, timestamp_high, timestamp_low)?;
        let captured_len = slice.read_u32::<B>().unwrap();
        let original_len = slice.read_u32::<B>().unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(BlockValidationError::ContentTooSmall {
                needed: tot_len,
                actual: slice.len(),
            });
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = opts_from_slice::<B, PacketOption>(state, Some(interface_id as u32), slice)?;
        let block = PacketBlock {
            interface_id,
            drop_count,
            timestamp,
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    /// Writes this block body using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        let captured_len = u32::try_from(self.data.len()).map_err(|_| {
            WriteError::Other(BlockValidationError::BlockTooLarge {
                actual: self.data.len() as u64,
                maximum: u32::MAX as u64,
            })
        })?;

        let (timestamp_high, timestamp_low) = state
            .encode_timestamp(self.interface_id as u32, self.timestamp)
            .map_err(|error| WriteError::Other(BlockValidationError::Timestamp(error)))?;

        let pad_len = (4 - (self.data.len() % 4)) % 4;
        let body_len = checked_body_len(self.data.len(), 20 + pad_len).map_err(WriteError::Other)?;

        writer.write_u16::<B>(self.interface_id)?;
        writer.write_u16::<B>(self.drop_count)?;
        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;
        writer.write_u32::<B>(captured_len)?;
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;

        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len = write_opts_to::<B, _, _>(&self.options, state, Some(self.interface_id as u32), writer)
            .map_err(|error| error.map_other(BlockValidationError::Option))?;

        checked_body_len(body_len, opt_len).map_err(WriteError::Other)
    }

    /// Checks the constraints applicable to this value.
    fn validate(&self, state: &PcapNgState) -> Result<(), BlockValidationError> {
        let captured_len = u32::try_from(self.data.len()).map_err(|_| BlockValidationError::BlockTooLarge {
            actual: self.data.len() as u64,
            maximum: u32::MAX as u64,
        })?;

        let interface = state
            .interfaces
            .get(self.interface_id as usize)
            .ok_or(BlockValidationError::InvalidInterfaceId(self.interface_id as u32))?;

        if self.original_len < captured_len {
            return Err(BlockValidationError::InvalidOriginalLen(
                self.original_len,
                self.data.len(),
            ));
        }

        if interface.snaplen != 0 && captured_len > interface.snaplen {
            return Err(BlockValidationError::CapturedLengthExceedsSnaplen {
                captured_len: self.data.len(),
                snaplen: interface.snaplen,
            });
        }

        validate_unique_opts(&self.options, |option| matches!(option, PacketOption::Flags(_)))
            .map_err(BlockValidationError::Option)?;

        validate_opts(&self.options, state, Some(self.interface_id as u32)).map_err(BlockValidationError::Option)
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::Packet(self)
    }
}

/* ----- PacketOption ----- */

/// Packet Block option
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum PacketOption<'a> {
    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(PacketHash<'a>),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl PacketOption<'_> {
    /// Encoded option code for `FLAGS`.
    const FLAGS: u16 = 2;
    /// Encoded option code for `HASH`.
    const HASH: u16 = 3;
}

impl<'a> PcapNgOption<'a> for PacketOption<'a> {
    /// Decodes an option value for the supplied option code.
    fn from_content<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        mut slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::FLAGS => {
                check_opt_len(slice, 4)?;
                PacketOption::Flags(slice.read_u32::<B>().unwrap())
            }
            Self::HASH => PacketOption::Hash(PacketHash::from_slice(slice)?),
            _ => PacketOption::Common(CommonOption::from_content::<B>(code, slice)?),
        };

        Ok(opt)
    }

    /// Writes this value using the selected byte order.
    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        match self {
            PacketOption::Flags(a) => write_u32_option::<B, W>(writer, Self::FLAGS, *a),
            PacketOption::Hash(a) => a.write_to::<B, W>(writer, Self::HASH),
            PacketOption::Common(a) => a.write_to::<B, W>(writer),
        }
    }

    /// Checks the constraints applicable to this value.
    fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError> {
        Ok(())
    }

    /// Returns the encoded option code.
    fn code(&self) -> u16 {
        match self {
            Self::Flags(_) => Self::FLAGS,
            Self::Hash(_) => Self::HASH,
            Self::Common(option) => option.code(),
        }
    }

    /// Returns the option name for its code.
    fn name(code: u16) -> &'static str {
        match code {
            Self::FLAGS => "Flags",
            Self::HASH => "Hash",
            _ => CommonOption::code_name(code),
        }
    }
}
