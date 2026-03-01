use thiserror::Error;

/// Result type for the pcap/pcapng parsing
pub type PcapResult<T> = Result<T, PcapNgError>;

/// Error type for the pcap/pcapng parsing
#[derive(Error, Debug)]
pub enum PcapNgError {
    /// Buffer too small
    /// # Fields
    /// - 0: needed size to parse the element
    /// - 1: actual size of the buffer
    #[error("Need more bytes to parse the element: needed {0}B, actual {1}B")]
    IncompleteBuffer(usize, usize),

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

    /// The packet's included length is bigger than the snaplen of the file
    /// 
    /// # Fields
    /// - 0: included length of the packet
    /// - 1: snaplen of the file
    #[error("Packet's included length ({0}) is bigger than the snaplen of the file ({1})")]
    PacketTooLarge(u32, u32),

    /// Error in custom conversion.
    #[error("Error in custom conversion for PEN {0}: {1}")]
    CustomConversionError(u32, Box<dyn std::error::Error + Sync + Send>),
}

impl From<std::str::Utf8Error> for PcapNgError {
    fn from(err: std::str::Utf8Error) -> Self {
        PcapNgError::Utf8Error(err)
    }
}

impl From<std::string::FromUtf8Error> for PcapNgError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PcapNgError::FromUtf8Error(err)
    }
}

impl From<std::io::Error> for PcapNgError {
    fn from(err: std::io::Error) -> Self {
        PcapNgError::IoError(err)
    }
}
