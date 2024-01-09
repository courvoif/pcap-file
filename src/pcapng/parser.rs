use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::interface_description::{InterfaceDescriptionBlock, TsResolution};
use super::blocks::section_header::SectionHeaderBlock;
use super::blocks::{INTERFACE_DESCRIPTION_BLOCK, SECTION_HEADER_BLOCK};
use crate::errors::PcapError;
use crate::Endianness;


/// Parses a PcapNg from a slice of bytes.
///
/// You can match on [`PcapError::IncompleteBuffer`] to know if the parser need more data.
///
/// # Example
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgParser;
/// use pcap_file::PcapError;
///
/// let pcap = std::fs::read("test.pcapng").expect("Error reading file");
/// let mut src = &pcap[..];
///
/// let (rem, mut pcapng_parser) = PcapNgParser::new(src).unwrap();
/// src = rem;
///
/// loop {
///     match pcapng_parser.next_block(src) {
///         Ok((rem, block)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///         },
///         Err(PcapError::IncompleteBuffer) => {
///             // Load more data into src
///         },
///         Err(_) => {
///             // Handle parsing error
///         },
///     }
/// }
/// ```
pub struct PcapNgParser {
    /// Current section of the pcapng
    section: SectionHeaderBlock<'static>,
    /// List of the interfaces of the current section of the pcapng
    interfaces: Vec<InterfaceDescriptionBlock<'static>>,
    /// Timestamp resolutions corresponding to the interfaces
    ts_resolutions: Vec<TsResolution>,
}

impl PcapNgParser {
    /// Creates a new [`PcapNgParser`].
    ///
    /// Parses the first block which must be a valid SectionHeaderBlock.
    pub fn new(src: &[u8]) -> Result<(&[u8], Self), PcapError> {
        // Always use BigEndian here because we can't know the SectionHeaderBlock endianness
        let (rem, section) = Block::from_slice::<BigEndian>(src)?;
        let section = match section {
            Block::SectionHeader(section) => section.into_owned(),
            _ => return Err(PcapError::InvalidField("PcapNg: SectionHeader invalid or missing")),
        };

        let parser = PcapNgParser { section, interfaces: Vec::new(), ts_resolutions: Vec::new() };

        Ok((rem, parser))
    }

    /// Returns the remainder and the next [`Block`].
    pub fn next_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapError> {
        // Read next Block
        let mut res = match self.section.endianness {
            Endianness::Big => {
                let (rem, raw_block) = self.next_raw_block_inner::<BigEndian>(src)?;
                let block = raw_block.try_into_block::<BigEndian>()?;
                Ok((rem, block))
            },
            Endianness::Little => {
                let (rem, raw_block) = self.next_raw_block_inner::<LittleEndian>(src)?;
                let block = raw_block.try_into_block::<LittleEndian>()?;
                Ok((rem, block))
            },
        };

        // If the block is an EnhancedPacketBlock, adjust its timestamp with the correct TsResolution
        if let Ok((_, Block::EnhancedPacket(ref mut blk))) = &mut res {
            let ts_resol = self
                .ts_resolutions
                .get(blk.interface_id as usize)
                .ok_or(PcapError::InvalidInterfaceId(blk.interface_id))?;

            blk.adjust_parsed_timestamp(*ts_resol);
        }

        res
    }

    /// Returns the remainder and the next [`RawBlock`].
    pub fn next_raw_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapError> {
        // Read next Block
        match self.section.endianness {
            Endianness::Big => self.next_raw_block_inner::<BigEndian>(src),
            Endianness::Little => self.next_raw_block_inner::<LittleEndian>(src),
        }
    }

    /// Inner function to parse the next raw block.
    fn next_raw_block_inner<'a, B: ByteOrder>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapError> {
        let (rem, raw_block) = RawBlock::from_slice::<B>(src)?;

        match raw_block.type_ {
            SECTION_HEADER_BLOCK => {
                self.section = raw_block.clone().try_into_block::<B>()?.into_owned().into_section_header().unwrap();
                self.interfaces.clear();
                self.ts_resolutions.clear();
            },
            INTERFACE_DESCRIPTION_BLOCK => {
                let interface = raw_block.clone().try_into_block::<B>()?.into_owned().into_interface_description().unwrap();
                let ts_resolution = interface.ts_resolution()?;

                self.interfaces.push(interface);
                self.ts_resolutions.push(ts_resolution);
            },
            _ => {},
        }

        Ok((rem, raw_block))
    }

    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.section
    }

    /// Returns all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.interfaces[..]
    }

    /// Returns the [`InterfaceDescriptionBlock`] corresponding to the given packet.
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces.get(packet.interface_id as usize)
    }
}
