use std::io::{BufRead, BufReader, Cursor, ErrorKind, Read, Error as IoError};
use std::ops::Not;
use byteorder::{BigEndian, LittleEndian};
use crate::errors::PcapError;
use crate::pcapng::blocks::{EnhancedPacketBlock, InterfaceDescriptionBlock};
use crate::{Endianness, PcapNgParser};
use crate::peek_reader::PeekReader;
use crate::pcapng::{Block, SectionHeaderBlock, BlockType};
use crate::read_buffer::ReadBuffer;

const BUF_SIZE: usize = 1_000_000;

/// Wraps another reader and uses it to read a PcapNg formated stream.
///
/// It implements the Iterator trait in order to read one block at a time except for the first SectionHeaderBlock
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
/// use pcap_file::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// // Read test.pcapng
/// for block in pcapng_reader {
///
///     //Check if there is no error
///     let block = block.unwrap();
///
///     //Parse block content
///     let parsed_block = block.parsed().unwrap();
///
///     //Do something
/// }
/// ```
pub struct PcapNgReader<R: Read> {
    parser: PcapNgParser,
    reader: ReadBuffer<R>
}

impl<R: Read> PcapNgReader<R> {
    /// Creates a new `PcapNgReader` from a reader.
    /// Parses the first block which must be a valid SectionHeaderBlock
    pub fn new(mut reader: R) -> Result<PcapNgReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapNgParser::new)?;

        Ok(
            Self {
                parser,
                reader
            }
        )
    }

    /// Returns the current SectionHeaderBlock
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.parser.section()
    }

    /// Returns the current interfaces
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.parser.interfaces()
    }

    /// Returns the InterfaceDescriptionBlock corresponding to the given packet
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces().get(packet.interface_id as usize)
    }

    /// Consumes the `PcapNgReader`, returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    pub fn next_block(&mut self) -> Option<Result<Block, PcapError>> {
        match self.reader.is_empty() {
            Ok(empty) => {
                if empty.not() {
                    let parser = &mut self.parser;
                    Some(self.reader.parse_with(|src| parser.next_block(src)))
                }
                else {
                    None
                }
            },

            Err(e) => Some(Err(e.into())),
        }
    }
}