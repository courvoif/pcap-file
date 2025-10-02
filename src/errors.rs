use thiserror::Error;

/// Result type for the pcap/pcapng parsing
pub type PcapResult<T> = Result<T, PcapError>;

/// Error type for the pcap/pcapng parsing
#[derive(Error, Debug)]
pub enum PcapError {
    /// Buffer too small
    #[error("Need more bytes")]
    IncompleteBuffer,

    /// Generic IO error
    #[error("Error reading/writing bytes")]
    IoError(#[source] std::io::Error),

    /// Invalid field
    #[error("Invalid field value: {0}")]
    InvalidField(&'static str),

    /// UTF8 conversion error
    #[error("UTF8 error")]
    Utf8Error(#[source] std::str::Utf8Error),

    /// From UTF8 conversion error
    #[error("UTF8 error")]
    FromUtf8Error(#[source] std::string::FromUtf8Error),

    /// Invalid interface ID (only for Pcap NG)
    #[error("The interface id ({0}) of the current block doesn't exists")]
    InvalidInterfaceId(u32),

    /// Invalid timestamp resolution (only for Pcap NG)
    #[error("Invalid timestamp resolution: {0} is not in [0-9]")]
    InvalidTsResolution(u8),

    /// The packet's timestamp is too big (only for Pcap NG)
    #[error("Packet's timestamp too big, please choose a bigger timestamp resolution")]
    TimestampTooBig,

    /// Error in custom conversion.
    #[error("Error in custom conversion for PEN {0}: {1}")]
    CustomConversionError(u32, Box<dyn std::error::Error + Sync + Send>),
}

impl From<std::str::Utf8Error> for PcapError {
    fn from(err: std::str::Utf8Error) -> Self {
        PcapError::Utf8Error(err)
    }
}

impl From<std::string::FromUtf8Error> for PcapError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PcapError::FromUtf8Error(err)
    }
}

impl From<std::io::Error> for PcapError {
    fn from(err: std::io::Error) -> Self {
        PcapError::IoError(err)
    }
}
