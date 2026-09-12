//! Stateful pcapng stream writing.

use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::PcapNgState;
use super::blocks::RawBlock;
use super::blocks::block_common::{Block, PcapNgBlock};
use super::blocks::section_header::SectionHeaderBlock;
use crate::Endianness;
use crate::pcapng::errors::PcapNgWriteError;

/// Writes a pcapng stream to a writer.
///
/// Use [`Self::state`] to access the current section and interfaces.
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
///     let (block, _) = block.unwrap();
///
///     // Write the parsed block.
///     pcapng_writer.write_block(&block).unwrap();
/// }
/// ```
pub struct PcapNgWriter<W: Write> {
    /// Current state of the pcapng format.
    state: PcapNgState,
    /// Underlying writer to which blocks are written.
    writer: W,
}

impl<W: Write> PcapNgWriter<W> {
    /// Creates a new [`PcapNgWriter`] from an existing writer.
    ///
    /// Uses the CPU's native endianness by default.
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
    /// - Returns any error produced by [`Self::with_endianness`].
    pub fn new(writer: W) -> Result<Self, PcapNgWriteError> {
        Self::with_endianness(writer, Endianness::default())
    }

    /// Creates a new [`PcapNgWriter`] with the given endianness.
    ///
    /// # Errors
    ///
    /// - Returns any error produced by [`Self::with_section_header`].
    pub fn with_endianness(writer: W, endianness: Endianness) -> Result<Self, PcapNgWriteError> {
        let section = SectionHeaderBlock {
            endianness,
            ..Default::default()
        };

        Self::with_section_header(writer, section)
    }

    /// Creates a new [`PcapNgWriter`] with the given section header.
    ///
    /// # Errors
    ///
    /// - Returns an error if the Section Header Block cannot be written.
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

    /// Writes a [`Block`].
    ///
    /// I/O errors can leave the output stream partially written. After any error,
    /// callers should assume the pcapng stream is no longer usable.
    ///
    /// # Errors
    ///
    /// - Returns an error if the block is invalid for the current state.
    /// - Returns an error if the block cannot be written.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
    ///
    /// use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcap_file::pcapng::blocks::PcapNgBlock;
    /// use pcap_file::pcapng::PcapNgWriter;
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

        let endianness = self.state.block_endianness(Some(block));

        let nb_written = match endianness {
            Endianness::Big => block.write_to::<BigEndian, _>(&self.state, &mut self.writer)?,
            Endianness::Little => block.write_to::<LittleEndian, _>(&self.state, &mut self.writer)?,
        };

        self.state.update_from_block(block);

        Ok(nb_written)
    }

    /// Writes a [`PcapNgBlock`].
    ///
    /// I/O errors can leave the output stream partially written. After any error,
    /// callers should assume the pcapng stream is no longer usable.
    ///
    /// # Errors
    ///
    /// - Returns an error if a block is invalid for the current state.
    /// - Returns an error if a block cannot be written.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
    ///
    /// use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcap_file::pcapng::blocks::PcapNgBlock;
    /// use pcap_file::pcapng::PcapNgWriter;
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
    /// pcap_ng_writer.write_typed_block(interface).unwrap();
    /// pcap_ng_writer.write_typed_block(packet).unwrap();
    /// ```
    pub fn write_typed_block<'a, B: PcapNgBlock<'a>>(&mut self, block: B) -> Result<usize, PcapNgWriteError> {
        self.write_block(&block.into_block())
    }

    /// Writes a [`RawBlock`].
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
    ///
    /// # Errors
    ///
    /// - Returns an error if the raw block is invalid or incompatible with the
    ///   current state.
    /// - Returns an error if the raw block cannot be written.
    pub fn write_raw_block(&mut self, raw_block: &RawBlock) -> Result<usize, PcapNgWriteError> {
        // The order of operation is important to prevent writing invalid files in case of error.
        // The state is updated only after a successful write.
        // The endianness is determined before the write to handle endianness changes when a new SectionHeader is encountered in the block list.
        let opt_block = self.state.decode_block_if_needed(raw_block)?;
        let endianness = self.state.block_endianness(opt_block.as_ref());

        // Write the block to the writer
        let nb_written = match endianness {
            Endianness::Big => raw_block.write_to::<BigEndian, _>(&mut self.writer)?,
            Endianness::Little => raw_block.write_to::<LittleEndian, _>(&mut self.writer)?,
        };

        if let Some(block) = opt_block {
            self.state.update_from_block(&block);
        }

        Ok(nb_written)
    }

    /// Consumes the writer, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Returns a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Returns a mutable reference to the underlying writer.
    ///
    /// Writing directly to the underlying writer can produce an invalid pcapng
    /// stream.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Returns the current [`PcapNgState`].
    ///
    /// Use the state to access the current section, interfaces, endianness, and
    /// timestamp conversion methods.
    pub fn state(&self) -> &PcapNgState {
        &self.state
    }
}
