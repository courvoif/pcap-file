use crate::peek_reader::PeekReader;
use crate::pcapng::{SectionHeaderBlock, InterfaceDescriptionBlock};
use std::io::Write;

struct PcapNgWriter<W: Write> {
    reader: PeekReader<R>,
    section: SectionHeaderBlock<'static>,
    interfaces: Vec<InterfaceDescriptionBlock<'static>>
}

impl<W: Write> PcapNgWriter<W> {

    fn new(writer: W, endianness: Endianness) -> PcapNgResult<Self> {

    }
}


use thiserror::Error;
use crate::Endianness;

pub(crate) type PcapWriteResult<T> = Result<T, PcapWriteError>;

#[derive(Error, Debug)]
pub enum PcapWriteError {

    #[error("Io error")]
    Io(#[source] std::io::Error),

    #[error("No corresponding interface id: {0}")]
    InvalidInterfaceId(u32),
}

impl From<std::io::Error> for PcapWriteError {
    fn from(err: std::io::Error) -> Self {
        PcapWriteError::Io(err)
    }
}