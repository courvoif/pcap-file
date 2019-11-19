use std::io::Read;
use byteorder::{BigEndian, LittleEndian};
use crate::errors::PcapError;
use crate::pcapng::blocks::{ParsedBlock, EnhancedPacketBlock, InterfaceDescriptionBlock};
use crate::Endianness;
use crate::peek_reader::PeekReader;
use crate::pcapng::{Block, SectionHeaderBlock, BlockType};

/// Wraps another reader and uses it to read a PcapNg formated stream.
///
/// It implements the Iterator trait in order to read one block at a time except the first SectionHeaderBlock
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
///     let parsed_block = block.parsed().unwrap();
///
///     //Do something
/// }
/// ```
pub struct PcapNgReader<R: Read> {
    reader: PeekReader<R>,
    section: SectionHeaderBlock<'static>,
    interfaces: Vec<InterfaceDescriptionBlock<'static>>
}

impl<R: Read> PcapNgReader<R> {

    /// Creates a new `PcapNgReader` from a reader.
    /// Parses the first block which must be a valid SectionHeaderBlock
    pub fn new(mut reader: R) -> Result<PcapNgReader<R>, PcapError> {

        let current_block = Block::from_reader::<_, BigEndian>(&mut reader)?;
        let section = current_block.parsed()?;

        let section = match section {
            ParsedBlock::SectionHeader(section) => section.into_owned(),
            _ => return Err(PcapError::InvalidField("SectionHeader missing"))
        };

        Ok(
            PcapNgReader {
                reader: PeekReader::new(reader),
                section,
                interfaces: vec![]
            }
        )
    }

    /// Returns the current SectionHeaderBlock
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.section
    }

    /// Returns the current interfaces
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.interfaces[..]
    }

    /// Returns the InterfaceDescriptionBlock corresponding to the given packet
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces.get(packet.interface_id as usize)
    }

    fn next_impl(&mut self) -> Result<Block<'static>, PcapError> {

        // Read next Block
        let endianess = self.section.endianness();
        let block = match endianess {
            Endianness::Big => Block::from_reader::<_, BigEndian>(&mut self.reader)?,
            Endianness::Little => Block::from_reader::<_, LittleEndian>(&mut self.reader)?
        };

        match block.type_ {
            BlockType::SectionHeader => {

                self.section = block.parsed()?.into_section_header().unwrap().into_owned();
                self.interfaces.clear();
            },
            BlockType::InterfaceDescription => {
                self.interfaces.push(block.parsed()?.into_interface_description().unwrap().into_owned())
            },
            _ => {}
        }

        Ok(block)
    }
}

impl<R: Read> Iterator for PcapNgReader<R> {
    type Item = Result<Block<'static>, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.is_empty() {
            Ok(is_empty) if is_empty => return None,
            Err(err) => return Some(Err(err.into())),
            _ => {}
        }

        Some(self.next_impl())
    }
}
