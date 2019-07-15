use failure::Fail;

pub(crate) type ResultParsing<T> = Result<T, PcapError>;

#[derive(Fail, Debug)]
pub enum PcapError {

    #[fail(display = "Need at least {} more bytes", _0)]
    IncompleteBuffer(usize),

    #[fail(display = "Io error: {}", _0)]
    IoError(std::io::Error),

    #[fail(display = "Invalid field value: {}", _0)]
    InvalidField(&'static str),

    #[fail(display = "UTF8 error: {}", _0)]
    Utf8Error(std::str::Utf8Error),

    #[fail(display = "UTF8 error: {}", _0)]
    FromUtf8Error(std::string::FromUtf8Error),
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
