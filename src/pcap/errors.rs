use std::time::Duration;

use thiserror::Error;

/* ----- enum PcapError ----- */

/// Errors that can occur while parsing, reading or writing a pcap file.
#[derive(Debug, Error)]
pub enum PcapError {
    /// The buffer is too small to parse the expected data.
    /// # Fields
    /// - 0: needed size to parse the data
    /// - 1: actual size of the buffer
    #[error("The buffer too small: need {0}B, got {1}B")]
    IncompleteBuffer(usize, usize),
    /// An I/O error occurred while reading the file.
    #[error("I/O error while reading the file")]
    ReadFailed(#[source] std::io::Error),
    /// An I/O error occurred while writing the file.
    #[error("I/O error while writing the file")]
    WriteFailed(#[source] std::io::Error),
    /// An I/O error occurred while writing a field in the file.
    /// # Fields
    /// - 0: field that failed to be written
    /// - 1: underlying I/O error
    #[error("I/O error while writing the field {0}")]
    FieldWriteFailed(&'static str, #[source] std::io::Error),
    /// A field of the pcap file is invalid.
    #[error(transparent)]
    InvalidField(PcapValidationError),
}

impl From<PcapValidationError> for PcapError {
    fn from(err: PcapValidationError) -> Self {
        PcapError::InvalidField(err)
    }
}


/* ----- enum ValidationError ----- */

/// Errors that can occur while validating a pcap file.
#[derive(Debug, Error)]
pub enum PcapValidationError {
    /// The magic number of the pcap header is invalid.
    #[error("Invalid magic number: {0:#X}")]
    InvalidMagicNumber(u32),
    /// The ts_frac is too big for microsecond resolution
    #[error("Ts_frac micro too big: {0} >= 1_000_000 us")]
    TsFracMicroTooBig(u32),
    /// The ts_frac is too big for nanosecond resolution
    #[error("Ts_frac nano too big: {0} >= 1_000_000_000 ns")]
    TsFracNanoTooBig(u32),
    /// The timestamp is too big to be represented in a u32 seconds field
    #[error("Timestamp too big: {0:?} > 2^32 seconds")]
    TimestampTooBig(Duration),
    /// The included length of the packet is bigger than the snaplen of the file
    #[error("included_len > snap_len: {0} > {1}")]
    IncludedLenTooBig(u32, u32),
    /// The original length of the packet is smaller than the included length of the packet
    #[error("origin_len < included_len: {0} < {1}")]
    OriginLenTooSmall(u32, u32),
    /// The data length is bigger than u32::MAX
    #[error("data length too big: {0} > u32::MAX")]
    DataTooBig(usize),
    /// The length of the packet is bigger than the snaplen of the file
    #[error("Packet length > snap_len: {0} > {1}")]
    PacketLenTooBig(u32, u32),
}
