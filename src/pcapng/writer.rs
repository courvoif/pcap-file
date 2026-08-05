use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::blocks::block_common::{Block, PcapNgBlock};
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::{PcapNgState, RawBlock};
use crate::Endianness;
use crate::pcapng::errors::PcapNgWriteError;

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
/// let out = Vec::new();
/// let mut pcapng_writer = PcapNgWriter::new(out).unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block() {
///     // Check if there is no error
///     let (block, _) = block.unwrap();
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
    /// Writes this section header to the file:
    /// ```rust
    /// use pcap_file::{DataLink, Endianness};
    /// use pcap_file::pcapng::blocks::section_header::SectionHeaderBlock;
    ///
    /// let section = SectionHeaderBlock {
    ///     endianness: Endianness::native(),
    ///     major_version: 1,
    ///     minor_version: 0,
    ///     section_length: -1,
    ///     options: vec![]
    /// };
    /// ```
    ///
    /// # Errors
    /// The writer can't be written to.
    pub fn new(writer: W) -> Result<Self, PcapNgWriteError> {
        Self::with_endianness(writer, Endianness::default())
    }

    /// Create a new [`PcapNgWriter`] from an existing writer with the given endianness.
    pub fn with_endianness(writer: W, endianness: Endianness) -> Result<Self, PcapNgWriteError> {
        let section = SectionHeaderBlock {
            endianness,
            ..Default::default()
        };

        Self::with_section_header(writer, section)
    }

    /// Create a new [`PcapNgWriter`] from an existing writer with the given section header.
    pub fn with_section_header(mut writer: W, section: SectionHeaderBlock<'_>) -> Result<Self, PcapNgWriteError> {
        let mut state = PcapNgState::default();

        let endianness = section.endianness;

        let block = section.into_owned().into_block();

        let _ = match endianness {
            Endianness::Big => block.write_to::<BigEndian, _>(&state, &mut writer),
            Endianness::Little => block.write_to::<LittleEndian, _>(&state, &mut writer),
        }?;

        state.update_from_block(&block);

        Ok(Self { state, writer })
    }

    /// Write a [`Block`].
    ///
    /// I/O errors can leave the output stream partially written. After any error,
    /// callers should assume the pcapng stream is no longer usable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
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
    /// let file = File::create("out.pcapng").expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    ///
    /// pcap_ng_writer.write_block(&interface.into_block()).unwrap();
    /// pcap_ng_writer.write_block(&packet.into_block()).unwrap();
    /// ```
    pub fn write_block(&mut self, block: &Block) -> Result<usize, PcapNgWriteError> {
        // The order of operation is important to prevent writing invalid files in case of error.
        // The state is updated only after a successful write.
        // The endianness is determined before the write to handle endianness changes when a new SectionHeader is encountered in the block list.

        let endianess = self.state.block_endianness(Some(block));

        let nb_written = match endianess {
            Endianness::Big => block.write_to::<BigEndian, _>(&self.state, &mut self.writer)?,
            Endianness::Little => block.write_to::<LittleEndian, _>(&self.state, &mut self.writer)?,
        };

        self.state.update_from_block(block);

        Ok(nb_written)
    }

    /// Write a [`PcapNgBlock`].
    ///
    /// I/O errors can leave the output stream partially written. After any error,
    /// callers should assume the pcapng stream is no longer usable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
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
    /// let file = File::create("out.pcapng").expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    ///
    /// pcap_ng_writer.write_pcapng_block(interface).unwrap();
    /// pcap_ng_writer.write_pcapng_block(packet).unwrap();
    /// ```
    pub fn write_pcapng_block<'a, B: PcapNgBlock<'a>>(&mut self, block: B) -> Result<usize, PcapNgWriteError> {
        self.write_block(&block.into_block())
    }

    /// Write a [`RawBlock`].
    ///
    /// I/O errors can leave the output stream partially written. After any error,
    /// callers should assume the pcapng stream is no longer usable.
    ///
    /// Validates the raw block length fields, but does not validate non-state
    /// block contents before writing.
    ///
    /// Section Header and Interface Description raw blocks are decoded before writing
    /// so the writer can update its state after a successful write. If decoding fails,
    /// nothing is written and the writer state is unchanged.
    pub fn write_raw_block(&mut self, raw_block: &RawBlock) -> Result<usize, PcapNgWriteError> {
        // The order of operation is important to prevent writing invalid files in case of error.
        // The state is updated only after a successful write.
        // The endianness is determined before the write to handle endianness changes when a new SectionHeader is encountered in the block list.
        let opt_block = self.state.decode_block_if_needed(raw_block)?;
        let endianess = self.state.block_endianness(opt_block.as_ref());

        // Write the block to the writer
        let nb_written = match endianess {
            Endianness::Big => raw_block.write_to::<BigEndian, _>(&mut self.writer)?,
            Endianness::Little => raw_block.write_to::<LittleEndian, _>(&mut self.writer)?,
        };

        if let Some(block) = opt_block {
            self.state.update_from_block(&block);
        }

        Ok(nb_written)
    }

    /// Consumes the writer, returning the wrapped writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Get a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Get a mutable reference to the underlying writer.
    ///
    /// Should not be used unless you really know what you're doing
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
