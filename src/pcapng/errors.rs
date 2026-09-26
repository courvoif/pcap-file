/* ----- Imports ----- */

use std::time::Duration;

use thiserror::Error;

use crate::{
    DataLink,
    pcapng::blocks::{Block, block_name, interface_description::InterfaceTsResolution},
};

/* ----- PcapNgParseError ----- */

/// Errors that can occur while parsing typed pcapng data.
#[derive(Debug, Error)]
pub enum PcapNgParseError {
    /// The buffer is too small to parse the expected data.
    #[error("The buffer is too small: need {0}B, got {1}B")]
    IncompleteBuffer(usize, usize),
    /// The raw block format is invalid.
    #[error("Invalid raw block format")]
    InvalidFormat(#[from] PcapNgFormatError),
    /// A block could not be decoded or validated before the state was updated.
    #[error(transparent)]
    Block(#[from] BlockError),
    /// The parser state could not be updated.
    #[error(transparent)]
    StateUpdate(#[from] StateUpdateError),
}

impl PcapNgParseError {
    /// Indicates whether the error is fatal and the parser cannot continue.
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::IncompleteBuffer(_, _) | Self::Block(_) => false,
            Self::InvalidFormat(_) | Self::StateUpdate(_) => true,
        }
    }
}

impl From<RawBlockParseError> for PcapNgParseError {
    fn from(value: RawBlockParseError) -> Self {
        match value {
            RawBlockParseError::IncompleteBuffer(needed, actual) => Self::IncompleteBuffer(needed, actual),
            RawBlockParseError::InvalidFormat(format) => Self::InvalidFormat(format)
        }
    }
}

/* ----- PcapNgReadError ----- */

/// Errors that can occur while reading pcapng data from an I/O source.
#[derive(Debug, Error)]
pub enum PcapNgReadError {
    /// An I/O error occurred while reading the pcapng stream.
    #[error("I/O error while reading the pcapng")]
    Io(#[source] std::io::Error),
    /// The raw block format is invalid.
    #[error("Invalid raw block format")]
    InvalidFormat(#[from] PcapNgFormatError),
    /// A block could not be decoded or validated before the state was updated.
    #[error(transparent)]
    Block(#[from] BlockError),
    /// The reader state could not be updated.
    #[error(transparent)]
    StateUpdate(#[from] StateUpdateError),
}

impl PcapNgReadError {
    /// Indicates whether the error is fatal and the reader cannot continue.
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::Block(_) => false,
            Self::InvalidFormat(_) | Self::StateUpdate(_) => true,
            Self::Io(error) => !matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }
}

impl From<PcapNgParseError> for PcapNgReadError {
    fn from(value: PcapNgParseError) -> Self {
        match value {
            PcapNgParseError::IncompleteBuffer(_, _) => {
                Self::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            }
            PcapNgParseError::InvalidFormat(error) => Self::InvalidFormat(error),
            PcapNgParseError::Block(error) => Self::Block(error),
            PcapNgParseError::StateUpdate(error) => Self::StateUpdate(error),
        }
    }
}

/* ----- PcapNgWriteError ----- */

/// Errors that can occur while writing pcapng data.
#[derive(Debug, Error)]
pub enum PcapNgWriteError {
    /// An I/O error occurred while writing the pcapng stream.
    #[error("I/O error while writing the pcapng stream")]
    Io(#[from] std::io::Error),
    /// The raw block format is invalid.
    #[error("Invalid raw block format")]
    InvalidFormat(#[from] PcapNgFormatError),
    /// A typed block could not be validated or encoded.
    #[error(transparent)]
    Block(#[from] BlockError),
    /// The writer state could not be updated.
    #[error(transparent)]
    StateUpdate(#[from] StateUpdateError),
}

/* ----- PcapNgFormatError ----- */

/// Format-related errors that prevent further parsing.
#[derive(Debug, Error)]
pub enum PcapNgFormatError {
    /// The file does not start with a Section Header Block.
    #[error("The section header is missing")]
    MissingSectionHeader,
    /// The Section Header Block magic number is invalid.
    #[error("Invalid magic number: {0:#X}")]
    InvalidMagicNumber(u32),
    /// The block length is not a multiple of four.
    #[error("Block length is not a multiple of 4: {0}B")]
    BlockNotAligned(usize),
    /// The block is too short to contain its framing and content.
    #[error("Block is too short: minimum {0}B, actual {1}B")]
    BlockTooShort(usize, usize),
    /// The initial and trailing block lengths do not match.
    #[error("Block length fields don't match: initial {0}B, trailing {1}B")]
    BlockLengthMismatch(u32, u32),
    /// The block length does not match the raw block body length.
    #[error("Block length doesn't match body length: expected {expected}B, got {actual}B")]
    InvalidBlockLength {
        /// Expected total length based on the raw block body.
        expected: usize,
        /// Actual total length field.
        actual: u32,
    },
}

/* ----- RawBlockParseError ----- */

/// Errors that can occur while parsing a raw block from bytes.
#[derive(Debug, Error)]
pub enum RawBlockParseError {
    /// The buffer is too small to parse the expected data.
    #[error("The buffer is too small: need {0}B, got {1}B")]
    IncompleteBuffer(usize, usize),
    /// The raw block format is invalid.
    #[error("Invalid raw block format")]
    InvalidFormat(#[from] PcapNgFormatError),
}

/* ----- BlockError ----- */

/// Error associated with a specific typed block.
#[derive(Debug, Error)]
#[error("Invalid block '{}' ({:#X})", block_name(self.type_), self.type_)]
pub struct BlockError {
    /// Numeric block type.
    pub type_: u32,
    /// Underlying block error.
    #[source]
    pub source: Box<BlockValidationError>,
}

/* ----- PacketConversionError ----- */

/// Errors that can occur while converting a typed block into a packet view.
#[derive(Debug, Error)]
pub enum PacketConversionError<'a> {
    /// The original block, which does not contain a packet.
    #[error("The block does not contain a packet")]
    NotPacket(Block<'a>),
    /// The packet's interface does not exist in the supplied section state.
    #[error("Invalid interface ID: {0}")]
    InvalidInterfaceId(u32),
}

/* ----- StateUpdateError ----- */

/// Errors that can occur while updating the pcapng state.
#[derive(Debug, Error)]
pub enum StateUpdateError {
    /// A state-changing block could not be decoded while preparing a state update.
    #[error("Invalid state-changing block: {0}")]
    InvalidStateBlock(#[from] BlockError),
}

/* ----- BlockValidationError ----- */

/// Semantic errors in decoded pcapng block content.
#[derive(Debug, Error)]
pub enum BlockValidationError {
    /// This block has no typed representation.
    #[error("Unknown block type")]
    UnknownType,
    /// The block content is too short.
    #[error("Block content too small: need {needed}B, got {actual}B")]
    ContentTooSmall {
        /// Needed size to decode the content.
        needed: usize,
        /// Actual content size.
        actual: usize,
    },
    /// The Section Header Block magic number is invalid.
    #[error("Invalid magic number: {0:#X}")]
    InvalidMagicNumber(u32),
    /// The link type does not fit in its encoded field.
    #[error("Invalid link type: {0:?}")]
    InvalidLinkType(DataLink),
    /// The encoded block is too large.
    #[error("Block length {actual}B exceeds the maximum {maximum}B")]
    BlockTooLarge {
        /// Requested encoded size.
        actual: u64,
        /// Maximum encoded size.
        maximum: u64,
    },
    /// A reserved field is not zero.
    #[error("Invalid reserved field: {0}")]
    InvalidReservedField(u16),
    /// Captured data exceeds the interface capture limit.
    #[error("Captured length {captured_len} exceeds interface snaplen {snaplen}")]
    CapturedLengthExceedsSnaplen {
        /// Captured bytes.
        captured_len: usize,
        /// Interface capture limit.
        snaplen: u32,
    },
    /// No interface exists in the current section state.
    #[error("Section without any interface")]
    NoInterface,
    /// The interface ID does not exist in the current section state.
    #[error("Invalid interface ID: {0}")]
    InvalidInterfaceId(u32),
    /// The original packet length is lower than its captured length.
    #[error("The original length of the packet is lower than its actual length: {0}B on wire, {1}B captured")]
    InvalidOriginalLen(u32, usize),
    /// The captured packet length does not match the expected length.
    #[error("Invalid captured length: expected {expected}B, got {actual}B")]
    InvalidCapturedLen {
        /// Expected captured length.
        expected: usize,
        /// Actual captured length.
        actual: usize,
    },

    /// An opaque record uses a reserved or known type code.
    #[error("Invalid opaque record type: {0}")]
    RecordTypeInvalid(u16),
    /// The encoded record is too large.
    #[error("Record length {actual}B exceeds the maximum {maximum}B")]
    RecordTooLarge {
        /// Requested encoded size.
        actual: usize,
        /// Maximum encoded size.
        maximum: usize,
    },
    /// A record name is empty or contains an embedded NUL byte.
    #[error("Record names must be nonempty and must not contain NUL bytes")]
    RecordNameInvalid,
    /// A Name Resolution record entry has the wrong size.
    #[error("Wrong record size: expected {expected}B, got {actual}B")]
    RecordWrongSize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },
    /// A Name Resolution record entry is smaller than its minimum size.
    #[error("Wrong record minimum size: expected at least {min}B, got {actual}B")]
    RecordWrongMinSize {
        /// Minimum size.
        min: usize,
        /// Actual size.
        actual: usize,
    },
    /// A record name is not valid UTF-8.
    #[error("A record name is not valid UTF-8")]
    RecordNameNotUtf8(#[source] std::str::Utf8Error),
    /// A Name Resolution record contains no names.
    #[error("Record without any name")]
    RecordNamesEmpty,

    /// The block contains an invalid timestamp value or representation.
    #[error("Failed to encode/decode timestamp")]
    Timestamp(#[from] TimestampError),

    /// An option list or entry could not be decoded or encoded.
    #[error("Failed to encode/decode options")]
    Option(#[from] OptionError),
}

/* ----- TimestampError ----- */

/// Errors in pcapng timestamp values and representations.
#[derive(Debug, Error)]
pub enum TimestampError {
    /// The interface ID does not exist in the current section state.
    #[error("Invalid interface ID: {0}")]
    InvalidInterfaceId(u32),
    /// The timestamp resolution encoding is invalid.
    #[error("Invalid timestamp resolution: {encoded:#X} (is_bin: {is_binary}, resol: {exponent})")]
    InvalidResolution {
        /// Encoded resolution byte.
        encoded: u8,
        /// Whether the resolution uses a binary base.
        is_binary: bool,
        /// Resolution exponent.
        exponent: u8,
    },
    /// A raw timestamp and offset cannot be represented as a duration since the Unix epoch.
    #[error(
        "Failed to decode timestamp (high: {timestamp_high:#X}, low: {timestamp_low:#X}, combined: {}) with resolution {resolution} and offset {offset}s",
        ((*timestamp_high as u64) << 32) | *timestamp_low as u64
    )]
    DecodeOutOfRange {
        /// Most significant timestamp bits.
        timestamp_high: u32,
        /// Least significant timestamp bits.
        timestamp_low: u32,
        /// Interface timestamp resolution.
        resolution: InterfaceTsResolution,
        /// Interface timestamp offset in seconds.
        offset: i64,
    },
    /// A timestamp cannot be represented in the raw 64-bit timestamp field.
    #[error("Failed to encode timestamp {timestamp:?} with resolution {resolution} and offset {offset}s")]
    EncodeOutOfRange {
        /// Timestamp supplied for encoding.
        timestamp: Duration,
        /// Interface timestamp resolution.
        resolution: InterfaceTsResolution,
        /// Interface timestamp offset in seconds.
        offset: i64,
    },
}

/* ----- OptionError ----- */

/// Errors that can occur while decoding or encoding a block's option list.
#[derive(Debug, Error)]
pub enum OptionError {
    /// The option list is too short.
    #[error("The option field is too small: need {needed}B, got {actual}B")]
    ContentTooSmall {
        /// Needed size to decode the option list.
        needed: usize,
        /// Actual remaining size.
        actual: usize,
    },
    /// An individual option entry is invalid.
    #[error("Invalid option entry. Code: {code}, Name: {name}: {source}")]
    InvalidEntry {
        /// Numeric option code.
        code: u16,
        /// Human-readable option name.
        name: &'static str,
        /// Underlying option entry error.
        #[source]
        source: Box<OptionEntryError>,
    },
}

/* ----- OptionEntryError ----- */

/// Errors that can occur while decoding or encoding one option entry.
#[derive(Debug, Error)]
pub enum OptionEntryError {
    /// The option value has the wrong size.
    #[error("Wrong entry size: expected {expected}B, got {actual}B")]
    WrongSize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },
    /// The option value is not valid UTF-8.
    #[error("Invalid UTF-8 format")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    /// The option value is too large for its encoded length field.
    #[error("Option length {actual}B exceeds the maximum {maximum}B")]
    TooLarge {
        /// Requested encoded size.
        actual: usize,
        /// Maximum encoded size.
        maximum: usize,
    },
    /// The option references an interface that does not exist.
    #[error("Invalid interface ID: {0}")]
    InvalidInterfaceId(u32),
    /// The option contains an invalid timestamp value or representation.
    #[error("Failed to encode/decode timestamp")]
    Timestamp(#[from] TimestampError),
}

/* ----- WriteError ----- */

/// Errors that can occur while writing a typed pcapng block.
#[derive(Debug, Error)]
pub enum WriteError<E: std::error::Error> {
    /// An I/O error occurred while writing the option list terminator.
    #[error("I/O error while writing the option list")]
    Io(#[from] std::io::Error),
    /// A typed block encoding error occurred.
    #[error(transparent)]
    Other(E),
}

impl From<WriteError<BlockError>> for PcapNgWriteError {
    fn from(error: WriteError<BlockError>) -> Self {
        match error {
            WriteError::Io(error) => Self::Io(error),
            WriteError::Other(error) => Self::Block(error),
        }
    }
}
