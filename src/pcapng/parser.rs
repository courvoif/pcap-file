use byteorder::{BigEndian, LittleEndian};
use crate::errors::PcapError;
use crate::pcapng::blocks::{Block, ParsedBlock, EnhancedPacketBlock, InterfaceDescriptionBlock};
use crate::Endianness;

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
    section: Block<'static>,
    interfaces: Vec<Block<'static>>
}

impl PcapNgParser {

    /// Creates a new `PcapNgParser`.
    ///
    /// Parses the first block which must be a valid SectionHeaderBlock
    pub fn new(src: &[u8]) -> Result<(&[u8], Self), PcapError> {

        let (rem, block) = Block::from_slice::<BigEndian>(src)?;
        match block.parsed {
            ParsedBlock::SectionHeader(_) => {},
            _ => return Err(PcapError::InvalidField("SectionHeader missing"))
        }

        let section = block.to_owned(block.section_header().unwrap().endianness());

        let parser = PcapNgParser {
            section,
            interfaces: vec![]
        };

        Ok((rem, parser))
    }

    /// Returns the remainder and the next block
    pub fn next_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapError> {

        let endianess = self.section.section_header().unwrap().endianness();

        let block_res = if endianess == Endianness::Big {
            Block::from_slice::<BigEndian>(src)
        }
        else {
            Block::from_slice::<LittleEndian>(src)
        };

        if let Ok((_, block)) = &block_res {
            if block.section_header().is_some() {
                self.section = block.to_owned(endianess);
                self.interfaces.clear();
            }
            else if block.interface_description().is_some() {
                self.interfaces.push(block.to_owned(endianess));
            }
        }

        block_res
    }

    /// Returns the current SectionHeaderBlock
    pub fn section(&self) -> &Block<'static> {
        &self.section
    }

    /// Returns the current interfaces
    pub fn interfaces(&self) -> &[Block<'static>] {
        &self.interfaces[..]
    }

    /// Returns the InterfaceDescriptionBlock corresponding to the given packet
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces.get(packet.interface_id as usize).map(|block| block.interface_description().unwrap())
    }
}