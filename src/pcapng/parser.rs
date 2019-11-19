use byteorder::{BigEndian, LittleEndian};
use crate::errors::PcapError;
use crate::pcapng::blocks::{ParsedBlock, EnhancedPacketBlock, InterfaceDescriptionBlock};
use crate::Endianness;
use crate::pcapng::{SectionHeaderBlock, Block, BlockType};

/// Parser for a PcapNg formated stream.
///
/// You can match on PcapError::IncompleteBuffer to known if the parser need more data
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
/// use pcap_file::pcapng::PcapNgParser;
/// use pcap_file::PcapError;
///
/// let data = vec![0_8;100];
/// let mut src = &data[..];
///
/// let (rem, mut pcapng_parser) = PcapNgParser::new(src).unwrap();
/// src = rem;
///
/// loop {
///
///     match pcapng_parser.next_block(src) {
///         Ok((rem, block)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///
///             // No more data, if no more incoming either then this is the end of the file
///             if rem.is_empty() {
///                 break;
///             }
///         },
///         Err(PcapError::IncompleteBuffer(needed)) => {},// Load more data into src
///         Err(_) => {}// Parsing error
///     }
/// }
/// ```
pub struct PcapNgParser {
    section: SectionHeaderBlock<'static>,
    interfaces: Vec<InterfaceDescriptionBlock<'static>>
}

impl PcapNgParser {

    /// Creates a new `PcapNgParser`.
    ///
    /// Parses the first block which must be a valid SectionHeaderBlock
    pub fn new(src: &[u8]) -> Result<(&[u8], Self), PcapError> {

        let (rem, block) = Block::from_slice::<BigEndian>(src)?;
        let section = block.parsed()?;

        let section = match section {
            ParsedBlock::SectionHeader(section) => section.into_owned(),
            _ => return Err(PcapError::InvalidField("SectionHeader missing"))
        };

        let parser = PcapNgParser {
            section,
            interfaces: vec![]
        };

        Ok((rem, parser))
    }

    /// Returns the remainder and the next block
    pub fn next_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapError> {

        // Read next Block
        let endianess = self.section.endianness();
        let (rem, block) = match endianess {
            Endianness::Big => Block::from_slice::<BigEndian>(src)?,
            Endianness::Little => Block::from_slice::<LittleEndian>(src)?
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

        Ok((rem, block))
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
}