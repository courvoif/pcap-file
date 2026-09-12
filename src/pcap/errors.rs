//! Errors produced when parsing, reading, writing, or validating pcap data.

use std::time::Duration;

use thiserror::Error;

use super::packet::RawPcapPacket;

/* ----- PcapError ----- */

/// Convenience error wrapper for applications that want to combine typed pcap
/// parsing, reading, writing, and validation errors into one error type.
///
/// Lower-level operations can return more specific errors, such as
/// [`PcapPacketConversionError`], directly.
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
    #[error("Buffer is too small: need {0}B, got {1}B")]
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
    #[error("I/O error while reading pcap data")]
    Io(#[source] std::io::Error),
    /// A field of the pcap file is invalid.
    #[error(transparent)]
    Validation(#[from] PcapValidationError),
}

/* ----- enum PcapWriteError ----- */

/// Errors that can occur while writing pcap data.
#[derive(Debug, Error)]
pub enum PcapWriteError {
    /// An I/O error occurred while writing pcap data.
    #[error("I/O error while writing pcap data")]
    Io(#[from] std::io::Error),
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
    #[error("Fractional timestamp exceeds microsecond range: {0} >= 1_000_000 us")]
    TsFracMicroTooLarge(u32),
    /// The fractional timestamp part is too large for nanosecond resolution.
    #[error("Fractional timestamp exceeds nanosecond range: {0} >= 1_000_000_000 ns")]
    TsFracNanoTooLarge(u32),
    /// The timestamp is too large to be represented in a 32-bit seconds field.
    #[error("Timestamp exceeds the 32-bit seconds range: {0:?}")]
    TimestampTooLarge(Duration),
    /// The captured packet length does not match the packet data length.
    #[error("Captured length does not match packet data length: {0} != {1}")]
    CapturedLengthMismatch(u32, u32),
    /// The original packet length is smaller than the captured packet length.
    #[error("Original length is smaller than captured length: {0} < {1}")]
    InvalidOriginalLength(u32, u32),
    /// The packet data length is larger than `u32::MAX`.
    #[error("Packet data length exceeds u32::MAX: {0}")]
    DataLengthTooLarge(usize),
    /// The packet data length is larger than the file snaplen.
    #[error("Packet data length exceeds snaplen: {0} > {1}")]
    CapturedLengthExceedsSnaplen(u32, u32),
}

/* ----- PcapPacketConversionError ----- */

/// Error returned when a raw pcap packet cannot be converted into a typed
/// packet.
#[derive(Debug, Error)]
#[error("Failed to convert raw pcap packet: {source}")]
pub struct PcapPacketConversionError<'a> {
    /// Original raw packet that failed conversion.
    pub packet: RawPcapPacket<'a>,
    /// Validation error that caused the conversion to fail.
    #[source]
    pub source: PcapValidationError,
}
