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

/* ----- enum PcapReadError ----- */

/// Errors that can occur while reading pcap data from an I/O source.
#[derive(Debug, Error)]
pub enum PcapReadError {
    /// An I/O error occurred while reading the pcap.
    #[error("I/O error while reading the pcap")]
    Io(#[source] std::io::Error),
    /// A field of the pcap file is invalid.
    #[error(transparent)]
    Validation(#[from] PcapValidationError),
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
