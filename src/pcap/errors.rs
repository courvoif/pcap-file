//! Error types returned by pcap parsing, reading, and writing.

/* ----- Imports ----- */

use std::time::Duration;

use thiserror::Error;

/* ----- PcapError ----- */

/// Convenience error type that wraps all errors that can occur while parsing,
/// reading, writing, or validating a pcap file.
#[derive(Debug, Error)]
pub enum PcapError {
    /// Error while parsing pcap data.
    #[error(transparent)]
    Parse(#[from] PcapParseError),
    /// Error while reading pcap data from an I/O source.
    #[error(transparent)]
    Read(#[from] PcapReadError),
    /// Error while writing pcap data.
    #[error(transparent)]
    Write(#[from] PcapWriteError),
    /// Validation error for decoded or encoded pcap content.
    #[error(transparent)]
    Validation(#[from] PcapValidationError),
}

/* ----- enum PcapParseError ----- */

/// Errors that can occur while parsing typed pcap data.
#[derive(Debug, Error)]
pub enum PcapParseError {
    /// The buffer is too small to parse the expected data.
    /// # Fields
    /// - 0: needed size to parse the data
    /// - 1: actual size of the buffer
    #[error("The buffer too small: need {0}B, got {1}B")]
    IncompleteBuffer(usize, usize),

    /// A field of the pcap file is invalid.
    #[error(transparent)]
    Validation(#[from] PcapValidationError),
}

/* ----- PcapReadError ----- */

/// A read error with the packet number and its starting byte offset.
/// Offsets are relative to the input passed to the reader.
#[derive(Debug, Error)]
#[error("Error reading pcap packet {packet_number} at byte offset {offset}: {kind}")]
pub struct PcapReadError {
    /// Zero-based packet number.
    /// Global header errors also use `0`, with an offset of `0`.
    pub packet_number: u64,
    /// Byte offset at the start of the packet or global header.
    pub offset: u64,
    /// Underlying read error.
    #[source]
    pub kind: PcapReadErrorKind,
}

impl PcapReadError {
    /// Creates a read error at the supplied packet position.
    pub(crate) fn new(packet_number: u64, offset: u64, kind: PcapReadErrorKind) -> Self {
        Self {
            packet_number,
            offset,
            kind,
        }
    }

    /// Indicates whether the error is fatal and the reader cannot continue.
    pub fn is_fatal(&self) -> bool {
        self.kind.is_fatal()
    }
}

/* ----- PcapReadErrorKind ----- */

/// Underlying causes of pcap read errors.
#[derive(Debug, Error)]
pub enum PcapReadErrorKind {
    /// An I/O error occurred while reading the pcap.
    #[error("I/O error while reading the pcap")]
    Io(#[source] std::io::Error),
    /// A field of the pcap file is invalid.
    #[error(transparent)]
    Validation(#[from] PcapValidationError),
}

impl PcapReadErrorKind {
    /// Indicates whether the error is fatal and the reader cannot continue.
    pub(crate) fn is_fatal(&self) -> bool {
        match self {
            Self::Validation(PcapValidationError::InvalidMagicNumber(_)) => true,
            Self::Validation(_) => false,
            Self::Io(error) => !matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }
}

/* ----- enum PcapWriteError ----- */

/// Errors that can occur while writing pcap data.
#[derive(Debug, Error)]
pub enum PcapWriteError {
    /// An I/O error occurred while writing the pcap stream.
    #[error("I/O error while writing the pcap")]
    Io(#[source] std::io::Error),
    /// An I/O error occurred while writing a field in the file.
    /// # Fields
    /// - 0: field that failed to be written
    /// - 1: underlying I/O error
    #[error("I/O error while writing the field {0}")]
    FieldWriteFailed(&'static str, #[source] std::io::Error),
    /// A field of the pcap file is invalid.
    #[error(transparent)]
    Validation(#[from] PcapValidationError),
}

/* ----- enum PcapValidationError ----- */

/// Errors that can occur while validating a pcap file.
#[derive(Debug, Error)]
pub enum PcapValidationError {
    /// The magic number of the pcap header is invalid.
    #[error("Invalid magic number: {0:#X}")]
    InvalidMagicNumber(u32),
    /// The fractional timestamp part is too large for microsecond resolution.
    #[error("Ts_frac micro too big: {0} >= 1_000_000 us")]
    TsFracMicroTooBig(u32),
    /// The fractional timestamp part is too large for nanosecond resolution.
    #[error("Ts_frac nano too big: {0} >= 1_000_000_000 ns")]
    TsFracNanoTooBig(u32),
    /// The timestamp is too large to be represented in a 32-bit seconds field.
    #[error("Timestamp too big: {0:?} > 2^32 seconds")]
    TimestampTooBig(Duration),
    /// The declared captured length differs from the actual packet data length.
    /// # Fields
    /// - 0: declared captured length
    /// - 1: actual packet data length
    #[error("included_len != data length: {0} != {1}")]
    IncludedLenMismatch(u32, usize),
    /// The captured packet length is larger than the file snaplen.
    #[error("included_len > snap_len: {0} > {1}")]
    IncludedLenTooBig(u32, u32),
    /// The original packet length is smaller than the captured packet length.
    #[error("origin_len < included_len: {0} < {1}")]
    OriginLenTooSmall(u32, u32),
    /// The packet data length is larger than `u32::MAX`.
    #[error("data length too big: {0} > u32::MAX")]
    DataTooBig(usize),
    /// The packet length is larger than the file snaplen.
    #[error("Packet length > snap_len: {0} > {1}")]
    PacketLenTooBig(u32, u32),
}
