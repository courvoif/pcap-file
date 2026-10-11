//! [`Enhanced Packet Block`](EnhancedPacketBlock).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{
    CommonOption, PacketHash, PcapNgOption, RawOption, check_opt_len, opts_from_slice, validate_opts,
    validate_unique_opts, write_opts_to, write_u32_option, write_u64_option,
};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, OptionEntryError, WriteError};

/* ----- EnhancedPacketBlock ----- */

/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
#[derive(Clone, Debug, Default, IntoOwned, Eq, PartialEq)]
pub struct EnhancedPacketBlock<'a> {
    /// It specifies the interface this packet comes from.
    ///
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number
    /// of this field.
    /// When writing, that interface must already be present in the [`PcapNgState`].
    pub interface_id: u32,

    /// Time elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: Duration,

    /// Actual length of the packet when it was transmitted on the network.
    /// Must be >= data.len().
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<EnhancedPacketOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for EnhancedPacketBlock<'a> {
    /// Numeric type code of this block.
    const TYPE: u32 = 0x00000006;
    /// Human-readable name of this block.
    const NAME: &'static str = "Enhanced Packet Block";
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

        let interface_id = slice.read_u32::<B>().expect("slice length checked above");
        let timestamp_high = slice.read_u32::<B>().expect("slice length checked above");
        let timestamp_low = slice.read_u32::<B>().expect("slice length checked above");
        let timestamp = state.decode_timestamp(interface_id, timestamp_high, timestamp_low)?;

        let captured_len = slice.read_u32::<B>().expect("slice length checked above");
        let original_len = slice.read_u32::<B>().expect("slice length checked above");

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len =
            (captured_len as usize)
                .checked_add(pad_len)
                .ok_or(BlockValidationError::SizeTooLargeForTarget {
                    actual: captured_len as u64 + pad_len as u64,
                })?;

        if slice.len() < tot_len {
            return Err(BlockValidationError::ContentTooSmall {
                needed: tot_len,
                actual: slice.len(),
            });
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = opts_from_slice::<B, EnhancedPacketOption>(state, Some(interface_id), slice)?;
        let block = EnhancedPacketBlock {
            interface_id,
            timestamp,
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    /// Checks the constraints applicable to this value.
    fn validate(&self, state: &PcapNgState) -> Result<(), BlockValidationError> {
        let interface = state
            .interfaces
            .get(self.interface_id as usize)
            .ok_or(BlockValidationError::InvalidInterfaceId(self.interface_id))?;

        let captured_len = u32::try_from(self.data.len()).map_err(|_| BlockValidationError::BlockTooLarge {
            actual: self.data.len() as u64,
            maximum: u32::MAX as u64,
        })?;

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

        validate_unique_opts(&self.options, |option| {
            matches!(
                option,
                EnhancedPacketOption::Flags(_)
                    | EnhancedPacketOption::DropCount(_)
                    | EnhancedPacketOption::PacketId(_)
                    | EnhancedPacketOption::Queue(_)
                    | EnhancedPacketOption::ProcessIdThreadId { .. }
            )
        })
        .map_err(BlockValidationError::Option)?;

        validate_opts(&self.options, state, Some(self.interface_id)).map_err(BlockValidationError::Option)
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
            .encode_timestamp(self.interface_id, self.timestamp)
            .map_err(|error| WriteError::Other(BlockValidationError::Timestamp(error)))?;

        let pad_len = (4 - (&self.data.len() % 4)) % 4;

        writer.write_u32::<B>(self.interface_id)?;
        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;
        writer.write_u32::<B>(captured_len)?;
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len = write_opts_to::<B, _, W>(&self.options, state, Some(self.interface_id), writer)
            .map_err(|error| error.map_other(BlockValidationError::Option))?;

        Ok(20 + &self.data.len() + pad_len + opt_len)
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::EnhancedPacket(self)
    }
}

/* ----- EnhancedPacketOption ----- */

/// The Enhanced Packet Block (EPB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum EnhancedPacketOption<'a> {
    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(PacketHash<'a>),

    /// 64-bit integer value specifying the number of packets lost
    /// (by the interface and the operating system) between this packet and the preceding one for
    /// the same interface or, for the first packet for an interface, between this packet
    /// and the start of the capture process.
    DropCount(u64),

    /// Identifier used to correlate the same packet captured on multiple interfaces.
    PacketId(u64),

    /// Interface queue on which the packet was received.
    Queue(u32),

    /// Action taken on the packet by a hardware or software component.
    /// Multiple verdicts may occur in one block.
    Verdict(PacketVerdict<'a>),

    /// Identifiers of the process and thread that originated the packet.
    ProcessIdThreadId {
        /// Process identifier, or zero when unknown or not applicable.
        process_id: u32,
        /// Thread identifier, or zero when unknown or not applicable.
        thread_id: u32,
    },

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl EnhancedPacketOption<'_> {
    /// Encoded option code for `FLAGS`.
    const FLAGS: u16 = 2;
    /// Encoded option code for `HASH`.
    const HASH: u16 = 3;
    /// Encoded option code for `DROP_COUNT`.
    const DROP_COUNT: u16 = 4;
    /// Encoded option code for `PACKET_ID`.
    const PACKET_ID: u16 = 5;
    /// Encoded option code for `QUEUE`.
    const QUEUE: u16 = 6;
    /// Encoded option code for `VERDICT`.
    const VERDICT: u16 = 7;
    /// Encoded option code for `PROCESS_ID_THREAD_ID`.
    const PROCESS_ID_THREAD_ID: u16 = 8;
}

impl<'a> PcapNgOption<'a> for EnhancedPacketOption<'a> {
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
                EnhancedPacketOption::Flags(slice.read_u32::<B>().expect("slice length checked above"))
            }
            Self::HASH => EnhancedPacketOption::Hash(PacketHash::from_slice(slice)?),
            Self::DROP_COUNT => {
                check_opt_len(slice, 8)?;
                EnhancedPacketOption::DropCount(slice.read_u64::<B>().expect("slice length checked above"))
            }
            Self::PACKET_ID => {
                check_opt_len(slice, 8)?;
                EnhancedPacketOption::PacketId(slice.read_u64::<B>().expect("slice length checked above"))
            }
            Self::QUEUE => {
                check_opt_len(slice, 4)?;
                EnhancedPacketOption::Queue(slice.read_u32::<B>().expect("slice length checked above"))
            }
            Self::VERDICT => EnhancedPacketOption::Verdict(PacketVerdict::from_slice::<B>(slice)?),
            Self::PROCESS_ID_THREAD_ID => {
                check_opt_len(slice, 8)?;
                EnhancedPacketOption::ProcessIdThreadId {
                    process_id: slice.read_u32::<B>().expect("slice length checked above"),
                    thread_id: slice.read_u32::<B>().expect("slice length checked above"),
                }
            }
            _ => EnhancedPacketOption::Common(CommonOption::from_content::<B>(code, slice)?),
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
            EnhancedPacketOption::Flags(a) => write_u32_option::<B, W>(writer, Self::FLAGS, *a),
            EnhancedPacketOption::Hash(a) => a.write_to::<B, W>(writer, Self::HASH),
            EnhancedPacketOption::DropCount(a) => write_u64_option::<B, W>(writer, Self::DROP_COUNT, *a),
            EnhancedPacketOption::PacketId(a) => write_u64_option::<B, W>(writer, Self::PACKET_ID, *a),
            EnhancedPacketOption::Queue(a) => write_u32_option::<B, W>(writer, Self::QUEUE, *a),
            EnhancedPacketOption::Verdict(a) => a.write_to::<B, W>(writer, Self::VERDICT),
            EnhancedPacketOption::ProcessIdThreadId { process_id, thread_id } => {
                RawOption::write_framed_to::<B, _, _>(writer, Self::PROCESS_ID_THREAD_ID, 8, |writer| {
                    writer.write_u32::<B>(*process_id)?;
                    writer.write_u32::<B>(*thread_id)
                })
            }
            EnhancedPacketOption::Common(a) => a.write_to::<B, W>(writer),
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
            Self::DropCount(_) => Self::DROP_COUNT,
            Self::PacketId(_) => Self::PACKET_ID,
            Self::Queue(_) => Self::QUEUE,
            Self::Verdict(_) => Self::VERDICT,
            Self::ProcessIdThreadId { .. } => Self::PROCESS_ID_THREAD_ID,
            Self::Common(option) => option.code(),
        }
    }

    /// Returns the option name for its code.
    fn name(code: u16) -> &'static str {
        match code {
            Self::FLAGS => "Flags",
            Self::HASH => "Hash",
            Self::DROP_COUNT => "Drop Count",
            Self::PACKET_ID => "Packet ID",
            Self::QUEUE => "Queue",
            Self::VERDICT => "Verdict",
            Self::PROCESS_ID_THREAD_ID => "Process and Thread IDs",
            _ => CommonOption::code_name(code),
        }
    }
}

/* ----- Packet verdicts ----- */

/// Packet verdict carried by an [`EnhancedPacketOption::Verdict`].
/// Numeric verdicts use the section's byte order; hardware and unknown payloads retain their bytes.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum PacketVerdict<'a> {
    /// Hardware-specific verdict bytes (type `0`).
    Hardware(Cow<'a, [u8]>),
    /// Linux eBPF traffic-control action (`TC_ACT_*`, type `1`).
    LinuxEbpfTc(u64),
    /// Linux eBPF XDP action (`xdp_action`, type `2`).
    LinuxEbpfXdp(u64),
    /// Preserved verdict for an unsupported type.
    /// Type codes and payload lengths are not validated for this variant.
    Unknown {
        /// Verdict type from the first byte of the option value.
        verdict_type: u8,
        /// Payload bytes following the verdict type.
        value: Cow<'a, [u8]>,
    },
}

impl<'a> PacketVerdict<'a> {
    /// Decodes a verdict type and its payload using the selected section byte order.
    /// Hardware and unsupported types retain their payload as a borrowed slice.
    ///
    /// # Errors
    /// Supply a type byte and exactly eight payload bytes for a Linux TC or XDP verdict.
    pub fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<Self, OptionEntryError> {
        let (&verdict_type, mut value) = slice
            .split_first()
            .ok_or(OptionEntryError::ContentTooSmall { needed: 1, actual: 0 })?;

        Ok(match verdict_type {
            0 => Self::Hardware(Cow::Borrowed(value)),
            1 | 2 => {
                check_opt_len(slice, 9)?;
                let verdict = value.read_u64::<B>().expect("verdict length checked above");
                if verdict_type == 1 {
                    Self::LinuxEbpfTc(verdict)
                } else {
                    Self::LinuxEbpfXdp(verdict)
                }
            }
            _ => Self::Unknown {
                verdict_type,
                value: Cow::Borrowed(value),
            },
        })
    }

    /// Writes the type byte and payload as a framed verdict option.
    fn write_to<B: ByteOrder, W: Write>(
        &self,
        writer: &mut W,
        code: u16,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        let mut encoded = [0; 8];
        let (verdict_type, value): (u8, &[u8]) = match self {
            Self::Hardware(value) => (0, value),
            Self::LinuxEbpfTc(value) => {
                B::write_u64(&mut encoded, *value);
                (1, &encoded)
            }
            Self::LinuxEbpfXdp(value) => {
                B::write_u64(&mut encoded, *value);
                (2, &encoded)
            }
            Self::Unknown { verdict_type, value } => (*verdict_type, value),
        };

        RawOption::write_framed_to::<B, _, _>(writer, code, value.len() + 1, |writer| {
            writer.write_u8(verdict_type)?;
            writer.write_all(value)
        })
    }
}
