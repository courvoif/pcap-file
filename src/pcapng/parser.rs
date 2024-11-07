use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use super::PcapNgState;
use super::blocks::block_common::{Block, RawBlock};
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
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
    /// Current state of the pcapng format.
    state: PcapNgState,
}

impl PcapNgParser {
    /// Creates a new [`PcapNgParser`].
    ///
    /// Parses the first block which must be a valid SectionHeaderBlock.
    pub fn new(src: &[u8]) -> Result<(&[u8], Self), PcapError> {
        // Always use BigEndian here because we can't know the SectionHeaderBlock endianness
        let mut state = PcapNgState::default();

        let (rem, block) = Block::from_slice::<BigEndian>(&state, src)?;

        if !matches!(&block, Block::SectionHeader(_)) {
            return Err(PcapError::InvalidField("PcapNg: SectionHeader invalid or missing"));
        };

        state.update_from_block(&block)?;

        let parser = PcapNgParser { state };

        Ok((rem, parser))
    }

    /// Returns the remainder and the next [`Block`].
    pub fn next_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapError> {
        // Read next Block
        match self.state.section.endianness {
            Endianness::Big => {
                let (rem, raw_block) = self.next_raw_block_inner::<BigEndian>(src)?;
                let block = raw_block.try_into_block::<BigEndian>(&self.state)?;
                Ok((rem, block))
            },
            Endianness::Little => {
                let (rem, raw_block) = self.next_raw_block_inner::<LittleEndian>(src)?;
                let block = raw_block.try_into_block::<LittleEndian>(&self.state)?;
                Ok((rem, block))
            },
        }
    }

    /// Returns the remainder and the next [`RawBlock`].
    pub fn next_raw_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapError> {
        // Read next Block
        match self.state.section.endianness {
            Endianness::Big => self.next_raw_block_inner::<BigEndian>(src),
            Endianness::Little => self.next_raw_block_inner::<LittleEndian>(src),
        }
    }

    /// Inner function to parse the next raw block.
    fn next_raw_block_inner<'a, B: ByteOrder>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapError> {
        let (rem, raw_block) = RawBlock::from_slice::<B>(src)?;
        self.state.update_from_raw_block::<B>(&raw_block)?;
        Ok((rem, raw_block))
    }

    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.state.section
    }

    /// Returns all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.state.interfaces[..]
    }

    /// Returns the [`InterfaceDescriptionBlock`] corresponding to the given packet.
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.state.interfaces.get(packet.interface_id as usize)
    }
}
