//! Packet Block.

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOpt};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::ContentValidationError;
use crate::pcapng::errors::{BlockContentParseError, OptionEntryError, PcapNgWriteError};

/// Packet Block (PB).
///
/// Stores captured packet data using the obsolete Packet Block format. New
/// files should use an Enhanced Packet Block or Simple Packet Block.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct PacketBlock<'a> {
    /// Interface on which this packet was captured.
    pub interface_id: u16,

    /// Local drop counter.
    ///
    /// Number of packets lost between this packet and the preceding packet.
    pub drop_count: u16,

    /// Time elapsed since the Unix epoch.
    pub timestamp: Duration,

    /// Original length of the packet on the wire.
    /// Must be greater than or equal to `data.len()`.
    pub original_len: u32,

    /// Captured packet data, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Block options.
    pub options: Vec<PacketOption<'a>>,
}

impl<'a> PacketBlock<'a> {
    /// Returns the packet data as a slice.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the packet data, preserving whether it is borrowed or owned.
    pub fn into_data(self) -> Cow<'a, [u8]> {
        self.data
    }

    /// Returns the captured packet data length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the packet contains no captured data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the packet's original length on the wire.
    pub fn original_len(&self) -> u32 {
        self.original_len
    }
}

impl<'a> PcapNgBlock<'a> for PacketBlock<'a> {
    fn from_slice<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockContentParseError> {
        if slice.len() < 20 {
            return Err(BlockContentParseError::BlockContentTooSmall {
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

        let snaplen = state.interfaces[interface_id as usize].snaplen;
        if snaplen != 0 && captured_len > snaplen {
            return Err(ContentValidationError::CapturedLengthExceedsSnaplen {
                captured_len: captured_len as usize,
                snaplen,
            }
            .into());
        }

        if original_len < captured_len {
            return Err(ContentValidationError::InvalidOriginalLength(original_len, captured_len as usize).into());
        }

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(BlockContentParseError::BlockContentTooSmall {
                needed: tot_len,
                actual: slice.len(),
            });
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = PacketOption::opts_from_slice::<B>(state, Some(interface_id as u32), slice)?;
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

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        // Integrity checks are done before any writing to prevent invalid state in the file
        let captured_len: u32 = self.data.len().try_into().map_err(|_| {
            PcapNgWriteError::validation_error(
                "PacketBlock.data",
                ContentValidationError::BlockContentTooBig(self.data.len() as u64),
            )
        })?;

        if (self.interface_id as usize) >= state.interfaces.len() {
            return Err(PcapNgWriteError::validation_error(
                "PacketBlock.interface_id",
                ContentValidationError::InvalidInterfaceId(self.interface_id as u32),
            ));
        }

        let snaplen = state.interfaces[self.interface_id as usize].snaplen;
        if snaplen != 0 && captured_len > snaplen {
            return Err(PcapNgWriteError::validation_error(
                "PacketBlock.data",
                ContentValidationError::CapturedLengthExceedsSnaplen {
                    captured_len: self.data.len(),
                    snaplen,
                },
            ));
        }

        if (self.original_len as usize) < self.data.len() {
            return Err(PcapNgWriteError::validation_error(
                "PacketBlock.original_len",
                ContentValidationError::InvalidOriginalLength(self.original_len, self.data.len()),
            ));
        }

        let (timestamp_high, timestamp_low) = state
            .encode_timestamp(self.interface_id as u32, self.timestamp)
            .map_err(|source| PcapNgWriteError::validation_error("PacketBlock.timestamp", source))?;

        writer.write_u16::<B>(self.interface_id)?;
        writer.write_u16::<B>(self.drop_count)?;
        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;
        writer.write_u32::<B>(captured_len)?;
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;

        let pad_len = (4 - (self.data.len() % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len =
            PacketOption::write_opts_to::<B, _>(&self.options, state, Some(self.interface_id as u32), writer)?;

        Ok(20 + self.data.len() + pad_len + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::Packet(self)
    }
}

/// Packet Block (PB) options.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum PacketOption<'a> {
    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl PacketOption<'_> {
    const FLAGS: u16 = 2;
    const HASH: u16 = 3;
}

impl<'a> PcapNgOption<'a> for PacketOption<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        mut slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::FLAGS => {
                if slice.len() != 4 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 4,
                        actual: slice.len(),
                    });
                }
                PacketOption::Flags(slice.read_u32::<B>().unwrap())
            }
            Self::HASH => PacketOption::Hash(Cow::Borrowed(slice)),
            _ => PacketOption::Common(CommonOption::new::<B>(code, slice)?),
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
            PacketOption::Flags(a) => a.write_opt::<B, W>(Self::FLAGS, writer),
            PacketOption::Hash(a) => a.write_opt::<B, W>(Self::HASH, writer),
            PacketOption::Common(a) => a.write_opt::<B, W>(a.code(), writer),
        }
    }

    fn code_name(code: u16) -> &'static str {
        match code {
            Self::FLAGS => "Flags",
            Self::HASH => "Hash",
            _ => CommonOption::code_name(code),
        }
    }
}
