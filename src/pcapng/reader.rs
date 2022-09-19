use std::io::Read;

use crate::errors::PcapError;
use crate::pcapng::{Block, EnhancedPacketBlock, InterfaceDescriptionBlock, SectionHeaderBlock};
use crate::read_buffer::ReadBuffer;
use crate::PcapNgParser;

/// Reads a PcapNg from a reader.
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block() {
///     //Check if there is no error
///     let block = block.unwrap();
///
///     //Do something
/// }
/// ```
pub struct PcapNgReader<R: Read> {
    parser: PcapNgParser,
    reader: ReadBuffer<R>,
}

impl<R: Read> PcapNgReader<R> {
    /// Creates a new [PcapNgReader](struct.PcapNgReader.html) from a reader.
    /// Parses the first block which must be a valid SectionHeaderBlock
    pub fn new(reader: R) -> Result<PcapNgReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = unsafe { reader.parse_with(PcapNgParser::new)? };
        Ok(Self { parser, reader })
    }

    /// Returns the next [Block](enum.Block.html)
    pub fn next_block(&mut self) -> Option<Result<Block, PcapError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    Some(unsafe { self.reader.parse_with(|src| self.parser.next_block(src)) })
                }
                else {
                    None
                }
            },
            Err(e) => Some(Err(e.into())),
        }
    }

    /// Returns the current [SectionHeaderBlock](struct.SectionHeaderBlock.html)
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        self.parser.section()
    }

    /// Returns the current [InterfaceDescriptionBlocks](struct.InterfaceDescriptionBlock.html)
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        self.parser.interfaces()
    }

    /// Returns the [InterfaceDescriptionBlock](struct.InterfaceDescriptionBlock.html) corresponding to the given packet
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces().get(packet.interface_id as usize)
    }

    /// Consumes the `PcapNgReader`, returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Gets a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        self.reader.get_ref()
    }
}
