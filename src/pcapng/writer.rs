use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::blocks::block_common::{Block, PcapNgBlock};
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::{PcapNgState, RawBlock};
use crate::{Endianness, PcapError, PcapResult};


/// Write a PcapNg to a writer.
///
/// # Examples
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// let mut out = Vec::new();
/// let mut pcapng_writer = PcapNgWriter::new(out).unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block() {
///     // Check if there is no error
///     let block = block.unwrap();
///
///     // Write back parsed Block
///     pcapng_writer.write_block(&block).unwrap();
/// }
/// ```
pub struct PcapNgWriter<W: Write> {
    /// Current state of the pcapng format.
    state: PcapNgState,
    /// Wrapped writer to which the block are written to.
    writer: W,
}

impl<W: Write> PcapNgWriter<W> {
    /// Create a new [`PcapNgWriter`] from an existing writer.
    ///
    /// Default to the native endianness of the CPU.
    ///
    /// Writes this global pcapng header to the file:
    /// ```rust, ignore
    /// Self {
    ///     endianness: Endianness::Native,
    ///     major_version: 1,
    ///     minor_version: 0,
    ///     section_length: -1,
    ///     options: vec![]
    /// }
    /// ```
    ///
    ///
    /// # Errors
    /// The writer can't be written to.
    pub fn new(writer: W) -> PcapResult<Self> {
        Self::with_endianness(writer, Endianness::native())
    }

    /// Create a new [`PcapNgWriter`] from an existing writer with the given endianness.
    pub fn with_endianness(writer: W, endianness: Endianness) -> PcapResult<Self> {
        let section = SectionHeaderBlock { endianness, ..Default::default() };

        Self::with_section_header(writer, section)
    }

    /// Create a new [`PcapNgWriter`] from an existing writer with the given section header.
    pub fn with_section_header(mut writer: W, section: SectionHeaderBlock<'_>) -> PcapResult<Self> {
        let mut state = PcapNgState::default();

        let endianness = section.endianness;

        let block = section
            .into_owned()
            .into_block();

        state.update_from_block(&block)?;

        match endianness {
            Endianness::Big => block.write_to::<BigEndian, _>(&state, &mut writer)?,
            Endianness::Little => block.write_to::<LittleEndian, _>(&state, &mut writer)?,
        };

        Ok(Self { state, writer })
    }

    /// Write a [`Block`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
    /// use std::time::Duration;
    ///
    /// use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
    /// use pcap_file::DataLink;
    ///
    /// let data = [0u8; 10];
    ///
    /// let interface = InterfaceDescriptionBlock {
    ///     linktype: DataLink::ETHERNET,
    ///     snaplen: 0xFFFF,
    ///     options: vec![],
    /// };
    ///
    /// let mut packet = EnhancedPacketBlock::default();
    /// packet.original_len = data.len() as u32;
    /// packet.data = Cow::Borrowed(&data);
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    ///
    /// pcap_ng_writer.write_block(&interface.into_block()).unwrap();
    /// pcap_ng_writer.write_block(&packet.into_block()).unwrap();
    /// ```
    pub fn write_block(&mut self, block: &Block) -> PcapResult<usize> {

        match block {
            Block::InterfaceStatistics(blk) => {
                if blk.interface_id as usize >= self.state.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(blk.interface_id));
                }
            },
            Block::EnhancedPacket(blk) => {
                if blk.interface_id as usize >= self.state.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(blk.interface_id));
                }
            },

            _ => (),
        }

        self.state.update_from_block(block)?;

        match self.state.section.endianness {
            Endianness::Big => block.write_to::<BigEndian, _>(&self.state, &mut self.writer),
            Endianness::Little => block.write_to::<LittleEndian, _>(&self.state, &mut self.writer),
        }
    }

    /// Write a [`PcapNgBlock`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
    /// use std::time::Duration;
    ///
    /// use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
    /// use pcap_file::DataLink;
    ///
    /// let data = [0u8; 10];
    ///
    /// let interface = InterfaceDescriptionBlock {
    ///     linktype: DataLink::ETHERNET,
    ///     snaplen: 0xFFFF,
    ///     options: vec![],
    /// };
    ///
    /// let mut packet = EnhancedPacketBlock::default();
    /// packet.original_len = data.len() as u32;
    /// packet.data = Cow::Borrowed(&data);
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    ///
    /// pcap_ng_writer.write_pcapng_block(interface).unwrap();
    /// pcap_ng_writer.write_pcapng_block(packet).unwrap();
    /// ```
    pub fn write_pcapng_block<'a, B: PcapNgBlock<'a>>(&mut self, block: B) -> PcapResult<usize> {
        self.write_block(&block.into_block())
    }

    /// Write a [`RawBlock`].
    ///
    /// Doesn't check the validity of the written blocks.
    pub fn write_raw_block(&mut self, block: &RawBlock) -> PcapResult<usize> {
        match self.state.section.endianness {
            Endianness::Big => {
                let written = block.write_to::<BigEndian, _>(&mut self.writer)?;
                self.state.update_from_raw_block::<BigEndian>(block)?;
                Ok(written)
            },
            Endianness::Little => {
                let written = block.write_to::<LittleEndian, _>(&mut self.writer)?;
                self.state.update_from_raw_block::<LittleEndian>(block)?;
                Ok(written)
            }
        }
    }

    /// Consume [`self`], returning the wrapped writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Get a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Get a mutable reference to the underlying writer.
    ///
    /// You should not be used unless you really know what you're doing
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Access the current [`PcapNgState`].
    pub fn state(&self) -> &PcapNgState {
        &self.state
    }

    /// Return the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.state.section
    }

    /// Return all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.state.interfaces
    }
}
