use std::time::Duration;

use thiserror::Error;

/* ----- PcapError ----- */

/// Errors that can occur while parsing, reading or writing a pcapng file.
#[derive(Debug, Error)]
pub enum PcapNgError {
    /// Error while parsing pcapng data.
    #[error(transparent)]
    Parse(#[from] PcapNgParseError),
    /// Error while writing pcapng data.
    #[error(transparent)]
    Write(#[from] PcapNgWriteError),
    /// Validation error for block or field content.
    #[error(transparent)]
    BlockValidation(#[from] ContentValidationError),
    /// Error while updating the parser or writer state.
    #[error(transparent)]
    StateUpdate(#[from] StateUpdateError),
}

/* ----- PcapNgParseError ----- */

/// Errors that can occur while parsing typed pcapng data.
#[derive(Debug, Error)]
pub enum PcapNgParseError {
    /// The buffer is too small to parse the expected data.
    /// # Fields
    /// - 0: needed size to parse the data
    /// - 1: actual size of the buffer
    #[error("The buffer too small: need {0}B, got {1}B")]
    IncompleteBuffer(usize, usize),

    /// The raw block format is invalid.
    #[error("Invalid raw block format")]
    InvalidFormat(#[from] PcapNgFormatError),

    /// Error while converting a raw block into a typed block.
    #[error(transparent)]
    BlockConversion(#[from] BlockConversionError),

    /// Error while updating the pcapng state.
    #[error(transparent)]
    StateUpdate(#[from] StateUpdateError),
}

impl From<RawBlockParseError> for PcapNgParseError {
    fn from(value: RawBlockParseError) -> Self {
        match value {
            RawBlockParseError::IncompleteBuffer(needed, actual) => Self::IncompleteBuffer(needed, actual),
            RawBlockParseError::InvalidFormat(format) => Self::InvalidFormat(format),
        }
    }
}

/* ----- PcapNgReadError ----- */

/// Errors that can occur while reading pcapng data from an I/O source.
#[derive(Debug, Error)]
pub enum PcapNgReadError {
    /// An I/O error occurred while reading the pcapng.
    #[error("I/O error while reading the pcapng")]
    Io(#[source] std::io::Error),

    /// The raw block format is invalid.
    #[error("Invalid raw block format")]
    InvalidFormat(#[from] PcapNgFormatError),

    /// Error while converting a raw block into a typed block.
    #[error(transparent)]
    BlockConversion(#[from] BlockConversionError),

    /// Error while updating the pcapng state.
    #[error(transparent)]
    StateUpdate(#[from] StateUpdateError),
}

impl From<PcapNgParseError> for PcapNgReadError {
    fn from(value: PcapNgParseError) -> Self {
        match value {
            PcapNgParseError::IncompleteBuffer(_, _) => Self::Io(std::io::ErrorKind::UnexpectedEof.into()),
            PcapNgParseError::InvalidFormat(e) => Self::InvalidFormat(e),
            PcapNgParseError::BlockConversion(e) => Self::BlockConversion(e),
            PcapNgParseError::StateUpdate(e) => Self::StateUpdate(e),
        }
    }
}

/* ----- enum PcapWriteError ----- */

/// Errors that can occur while writing pcapng data.
#[derive(Debug, Error)]
pub enum PcapNgWriteError {
    /// An I/O error occurred while writing the pcapng stream.
    #[error("I/O error during writing")]
    Io(#[from] std::io::Error),

    /// A field failed validation before being written.
    #[error("Field `{field}` failed its validation during writing")]
    Validation {
        /// Name of the field that failed validation.
        field: &'static str,
        /// Underlying validation error.
        source: ContentValidationError,
    },

    /// Error while updating the pcapng state.
    #[error("State update error during writing")]
    StateUpdate(#[from] StateUpdateError),
}

/* ----- PcapNgFormatError ----- */

/// Format-related errors that prevent further parsing.
#[derive(Debug, Error)]
pub enum PcapNgFormatError {
    /// The file does not start with a Section Header Block.
    #[error("The section header is missing")]
    MissingSectionHeader,
    /// The magic number of the pcapng SectionBlock is invalid.
    #[error("Invalid magic number: {0:#X}")]
    InvalidMagicNumber(u32),
    /// The block length field of a block is not a multiple of 4, which is required by the pcapng specification.
    #[error("Block length is not a multiple of 4: {0}B")]
    BlockNotAligned(usize),
    /// The block is too short to contain its content.
    /// # Fields
    /// - 0: minimum block size for the expected block type
    /// - 1: actual block size
    #[error("Block is too short: minimum {0}B, actual {1}B,")]
    BlockTooShort(usize, usize),
    /// The two block length fields do not match.
    /// # Fields
    /// - 0: initial length field
    /// - 1: trailing length field
    #[error("Block length fields don't match: initial {0}B, trailing {1}B")]
    BlockLengthMismatch(u32, u32),
}

/* ----- RawBlockParseError ----- */

/// Errors that can occur while parsing a raw block from bytes.
#[derive(Debug, Error)]
pub enum RawBlockParseError {
    /// The buffer is too small to parse the expected data.
    /// # Fields
    /// - 0: needed size to parse the data
    /// - 1: actual size of the buffer
    #[error("The buffer too small: need {0}B, got {1}B")]
    IncompleteBuffer(usize, usize),

    /// The raw block format is invalid.
    #[error("Invalid raw block format")]
    InvalidFormat(#[from] PcapNgFormatError),
}

/* ----- BlockConversionError ----- */

/// Errors that can occur while converting a raw block into a typed block.
#[derive(Debug, Error)]
#[error("Invalid content for block '{name}' ({type_:#X})")]
pub struct BlockConversionError {
    /// Human-readable block name
    pub name: &'static str,
    /// Numeric block type
    pub type_: u32,
    /// Underlying block content parse error
    pub source: BlockContentParseError,
}

/* ----- BlockContentParseError ----- */

/// Errors that can occur while parsing the content of a block.
#[derive(Debug, Error)]
pub enum BlockContentParseError {
    /// The block is too short.
    #[error("Block content too small: need {needed}B, got {actual}B")]
    BlockContentTooSmall {
        /// Needed size to parse the block content.
        needed: usize,
        /// Actual size of the remaining block content buffer.
        actual: usize,
    },

    /// Validation error while decoding block content.
    #[error(transparent)]
    Validation(#[from] ContentValidationError),

    /// Error parsing block options.
    #[error("Error parsing the options")]
    Option(#[from] OptionParseError),
}

/* ----- StateUpdateError ----- */

/// Errors that can occur while updating the pcapng state.
#[derive(Debug, Error)]
pub enum StateUpdateError {
    /// A state-relevant raw block could not be converted into a typed block.
    #[error("Failed to convert raw block to update the pcapng state")]
    BlockConversion(#[from] BlockConversionError),

    /// A typed block failed state validation.
    #[error("Failed to validate the pcapng state")]
    Validation(#[from] ContentValidationError),
}

/* ----- ContentValidationError ----- */

/// Errors that can occur while validating decoded pcapng content.
#[derive(Debug, Error)]
pub enum ContentValidationError {
    /// The magic number of the pcapng SectionBlock is invalid.
    #[error("Invalid magic number: {0:#X}")]
    InvalidMagicNumber(u32),
    /// A reserved field is not zero.
    #[error("Invalid reserved field: {0}")]
    InvalidReservedField(u16),
    /// The timestamp resolution value is invalid.
    #[error("Invalid timestamp resolution: {0}")]
    InvalidTsResolution(u8),
    /// The interface ID does not exist in the current section state.
    #[error("Invalid interface ID: {0}")]
    InvalidInterfaceId(u32),
    /// The timestamp cannot be represented in the raw 64-bit timestamp field.
    #[error("Timestamp too big: {0:?} > 2^64 units")]
    TimestampTooBig(Duration),
    /// The timestamp is earlier than the interface timestamp offset.
    #[error("Timestamp {timestamp:?} is smaller than interface offset {offset:?}")]
    TimestampBeforeOffset {
        /// Absolute timestamp to encode
        timestamp: Duration,
        /// Interface timestamp offset
        offset: Duration,
    },
    /// The Name Resolution record entry size is invalid.
    #[error("Wrong record size: expected {expected}B, got {actual}B")]
    RecordWrongSize {
        /// Expected size
        expected: usize,
        /// Actual size
        actual: usize,
    },
    /// The Name Resolution record entry is smaller than its minimum valid size.
    #[error("Wrong record minimum size: expected at least {min}B, got {actual}B")]
    RecordWrongMinSize {
        /// Expected size
        min: usize,
        /// Actual size
        actual: usize,
    },
    /// The Name Resolution record entry is too big to be written
    #[error("Record length doesn't fit on a u16: {0}B")]
    RecordTooBig(usize),
    /// A record name is not valid UTF-8.
    #[error("A record name is not in UTF8")]
    RecordNameNotUtf8(#[source] std::str::Utf8Error),
    /// A Name Resolution record does not contain any names.
    #[error("Record without any name")]
    RecordNamesEmpty,
    /// Error converting a custom block payload.
    #[error("Error in custom block conversion for PEN {0}: {1}")]
    CustomBlockConversionError(u32, Box<dyn std::error::Error + Sync + Send>),
    /// The content of a block is too big to fit on a block.
    #[error("Block content doesn't fit on a u32: {0}B")]
    BlockContentTooBig(u64),
    /// The content of a PcapNgOption is too big to be written
    #[error("Option content doesn't fit on a u16: {0}B")]
    OptionTooBig(usize)
}

/* ----- OptionParseError ----- */

/// Errors that can occur while parsing a block's option list.
#[derive(Debug, Error)]
pub enum OptionParseError {
    /// The buffer is too short to parse the options.
    #[error("The option field is to small to parse the options: need {needed}B, got {actual}B")]
    OptionsContentTooSmall {
        /// Needed size to parse the option list.
        needed: usize,
        /// Actual size of the option buffer.
        actual: usize,
    },
    /// An individual option entry is invalid.
    #[error("Invalid option entry. Code: {code}, Name: {name}")]
    InvalidEntry {
        /// Numeric option code.
        code: u16,
        /// Human-readable option name.
        name: &'static str,
        /// Underlying option entry error.
        source: OptionEntryError,
    },
}

/* ----- OptionEntryError ----- */

/// Errors that can occur while parsing a single option entry.
#[derive(Debug, Error)]
pub enum OptionEntryError {
    /// The size of the option entry is not correct.
    #[error("Wrong entry size: expected {expected}B, got {actual}B")]
    WrongSize {
        /// Expected size
        expected: usize,
        /// Actual size
        actual: usize,
    },

    /// The option payload is not valid UTF-8.
    #[error("Invalid UTF8 format")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    /// Validation error while decoding an option entry.
    #[error(transparent)]
    Validation(#[from] ContentValidationError),
}
