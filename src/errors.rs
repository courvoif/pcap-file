use thiserror::Error;

pub(crate) type ResultParsing<T> = Result<T, PcapError>;

#[derive(Error, Debug)]
pub enum PcapError {

    #[error("Need at least {0} more bytes")]
    IncompleteBuffer(usize),

    #[error("Error reading bytes")]
    IoError(#[source] std::io::Error),

    #[error("Invalid field value: {0}")]
    InvalidField(&'static str),

    #[error("UTF8 error")]
    Utf8Error(#[source] std::str::Utf8Error),

    #[error("UTF8 error")]
    FromUtf8Error(#[source] std::string::FromUtf8Error),
}

impl From<std::io::Error> for PcapError {
    fn from(err: std::io::Error) -> Self {
        PcapError::IoError(err)
    }
}

impl From< std::str::Utf8Error> for PcapError {
    fn from(err: std::str::Utf8Error) -> Self {
        PcapError::Utf8Error(err)
    }
}

impl From< std::string::FromUtf8Error> for PcapError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PcapError::FromUtf8Error(err)
    }
}
