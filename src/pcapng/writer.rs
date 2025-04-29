use std::io::Write;

use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use super::blocks::block_common::{Block, PcapNgBlock};
use super::blocks::interface_description::{InterfaceDescriptionBlock, TsResolution};
use super::blocks::section_header::SectionHeaderBlock;
use super::blocks::SECTION_HEADER_BLOCK;
use super::RawBlock;
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
    /// Current section of the pcapng
    section: SectionHeaderBlock<'static>,
    /// List of the interfaces of the current section of the pcapng
    interfaces: Vec<InterfaceDescriptionBlock<'static>>,
    /// Timestamp resolutions corresponding to the interfaces
    ts_resolutions: Vec<TsResolution>,

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
        match section.endianness {
            Endianness::Big => section.clone().into_block().write_to::<BigEndian, _>(&mut writer).map_err(PcapError::IoError)?,
            Endianness::Little => section.clone().into_block().write_to::<LittleEndian, _>(&mut writer).map_err(PcapError::IoError)?,
        };

        Ok(Self {
            section: section.into_owned(),
            interfaces: Vec::new(),
            ts_resolutions: Vec::new(),
            writer
        })
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
            Block::SectionHeader(blk) => {
                self.section = blk.clone().into_owned();
                self.interfaces.clear();
                self.ts_resolutions.clear();
            },
            Block::InterfaceDescription(blk) => {
                let ts_resolution = blk.ts_resolution()?;
                self.ts_resolutions.push(ts_resolution);

                self.interfaces.push(blk.clone().into_owned());
            },
            Block::InterfaceStatistics(blk) => {
                if blk.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(blk.interface_id));
                }
            },
            Block::EnhancedPacket(blk) => {
                if blk.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(blk.interface_id));
                }

                let ts_resol = self.ts_resolutions[blk.interface_id as usize];
                blk.set_write_ts_resolution(ts_resol);
            },

            _ => (),
        }

        match self.section.endianness {
            Endianness::Big => block.write_to::<BigEndian, _>(&mut self.writer).map_err(PcapError::IoError),
            Endianness::Little => block.write_to::<LittleEndian, _>(&mut self.writer).map_err(PcapError::IoError),
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
        return match self.section.endianness {
            Endianness::Big => inner::<BigEndian, _>(&mut self.section, block, &mut self.writer),
            Endianness::Little => inner::<LittleEndian, _>(&mut self.section, block, &mut self.writer),
        };

        // Write a RawBlock to a writer
        fn inner<B: ByteOrder, W: Write>(section: &mut SectionHeaderBlock, block: &RawBlock, writer: &mut W) -> PcapResult<usize> {
            if block.type_ == SECTION_HEADER_BLOCK {
                *section = block.clone().try_into_block::<B>()?.into_owned().into_section_header().unwrap();
            }

            block.write_to::<B, _>(writer).map_err(PcapError::IoError)
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

    /// Return the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.section
    }

    /// Return all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.interfaces
    }
}
