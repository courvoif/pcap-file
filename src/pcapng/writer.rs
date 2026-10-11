//! Typed and raw pcapng block writing.

/* ----- Imports ----- */

use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::blocks::block_common::{Block, PcapNgBlock};
use super::blocks::section_header::SectionHeaderBlock;
use super::{PcapNgState, RawBlock};
use crate::Endianness;
use crate::pcapng::errors::PcapNgWriteError;

/* ----- Writer ----- */

/// Write a PcapNg to a writer.
///
/// # Examples
/// ```rust,no_run
/// use std::fs::File;
/// use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let file = File::open("tests/pcapng/little_endian/basic/test001.pcapng")?;
///     let mut reader = PcapNgReader::new(file, true)?;
///
///     // The constructor consumed the first section header; preserve it explicitly.
///     let section = reader.state().section().clone();
///     let mut writer = PcapNgWriter::with_section_header(Vec::new(), section, true)?;
///     while let Some(result) = reader.next_block() {
///         // Interface blocks update the writer state before their packets are written.
///         let (block, _) = result?;
///         writer.write_block(&block)?;
///     }
///
///     println!("copied {} bytes", writer.into_inner().len());
///     Ok(())
/// }
/// ```
pub struct PcapNgWriter<W: Write> {
    /// Current state of the pcapng format.
    state: PcapNgState,
    /// Wrapped writer to which the block are written to.
    writer: W,
    /// Whether typed blocks receive block semantic validation.
    strict: bool,
}

impl<W: Write> PcapNgWriter<W> {
    /// Create a new [`PcapNgWriter`] from an existing writer.
    ///
    /// Writes a default Section Header Block using native byte order.
    /// When `strict` is true, typed blocks are validated before writing.
    /// Encoding always checks representations and individual options.
    /// See [`Self::write_raw_block`] for the validation rules of raw operations.
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
    /// An I/O failure can leave a partial initial section header in the output.
    pub fn new(writer: W, strict: bool) -> Result<Self, PcapNgWriteError> {
        Self::with_endianness(writer, Endianness::default(), strict)
    }

    /// Creates a writer with the given byte order.
    /// Writes a default Section Header Block in that byte order.
    /// When `strict` is true, typed blocks are validated before writing.
    /// Representations and individual options are checked in either mode.
    ///
    /// # Errors
    /// An I/O failure can leave a partial initial header in the output.
    pub fn with_endianness(writer: W, endianness: Endianness, strict: bool) -> Result<Self, PcapNgWriteError> {
        let section = SectionHeaderBlock {
            endianness,
            ..Default::default()
        };

        Self::with_section_header(writer, section, strict)
    }

    /// Creates a writer with the given section header.
    /// Writes the initial Section Header Block immediately.
    /// `strict` controls block validation, including for the initial header.
    /// Representations and individual options are checked in either mode.
    ///
    /// # Errors
    /// Correct an invalid section header before retrying.
    /// An I/O failure can leave a partial initial header in the output.
    pub fn with_section_header(
        writer: W,
        section: SectionHeaderBlock<'_>,
        strict: bool,
    ) -> Result<Self, PcapNgWriteError> {
        let mut writer = Self {
            state: PcapNgState::default(),
            writer,
            strict,
        };
        writer.write_block(&section.into_block())?;
        Ok(writer)
    }

    /// Returns whether typed blocks are semantically validated before writing.
    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Writes a typed block, validating its content first in strict mode.
    ///
    /// Validation and encoding errors leave the output and writer state unchanged.
    /// An I/O error can leave the stream partially written; discard or repair that output.
    ///
    /// # Example
    /// ```rust
    /// use std::borrow::Cow;
    /// use std::time::Duration;
    ///
    /// use pcap_file::DataLink;
    /// use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
    /// use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    ///
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut writer = PcapNgWriter::new(Vec::new(), true)?;
    ///
    ///     // Packet blocks use an interface by index; this packet uses interface 0.
    ///     let interface = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535);
    ///     writer.write_block(&interface.into_block())?;
    ///
    ///     // These bytes are just example packet data.
    ///     let data = [0_u8; 64];
    ///     let packet = EnhancedPacketBlock {
    ///         timestamp: Duration::from_secs(1),
    ///         original_len: data.len() as u32,
    ///         data: Cow::Borrowed(&data),
    ///         ..Default::default()
    ///     };
    ///     writer.write_block(&packet.into_block())?;
    ///
    ///     let capture = writer.into_inner();
    ///     println!("wrote {} bytes", capture.len());
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Correct validation or encoding failures and retry with the writer state unchanged.
    /// If an I/O error occurs, discard or repair any partially written block.
    pub fn write_block(&mut self, block: &Block) -> Result<usize, PcapNgWriteError> {
        // The order of operation is important to prevent writing invalid files in case of error.
        // The state is updated only after a successful write.
        // The endianness is determined before the write to handle endianness changes when a new SectionHeader is encountered in the block list.

        if self.strict {
            block.validate(&self.state)?;
        }

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
    /// Validation and encoding errors leave the output and writer state unchanged.
    /// An I/O error can leave the stream partially written; discard or repair that output.
    ///
    /// # Example
    /// ```rust
    /// use std::borrow::Cow;
    /// use std::time::Duration;
    ///
    /// use pcap_file::DataLink;
    /// use pcap_file::pcapng::PcapNgWriter;
    /// use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    ///
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut writer = PcapNgWriter::new(Vec::new(), true)?;
    ///
    ///     // Packet blocks use an interface by index; this packet uses interface 0.
    ///     writer.write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535))?;
    ///
    ///     // These bytes are just example packet data.
    ///     let data = [0_u8; 64];
    ///     let packet = EnhancedPacketBlock {
    ///         timestamp: Duration::from_secs(1),
    ///         original_len: data.len() as u32,
    ///         data: Cow::Borrowed(&data),
    ///         ..Default::default()
    ///     };
    ///     writer.write_pcapng_block(packet)?;
    ///
    ///     let capture = writer.into_inner();
    ///     println!("wrote {} bytes", capture.len());
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Correct validation or encoding failures and retry with the writer state unchanged.
    /// If an I/O error occurs, discard or repair any partially written block.
    pub fn write_pcapng_block<'a, B: PcapNgBlock<'a>>(&mut self, block: B) -> Result<usize, PcapNgWriteError> {
        self.write_block(&block.into_block())
    }

    /// Write a [`RawBlock`].
    ///
    /// Validation and encoding errors leave the output and writer state unchanged.
    /// An I/O error can leave the stream partially written; discard or repair that output.
    ///
    /// Validates raw framing without calling [`Block::validate`], regardless of strict mode.
    /// Decode and validate explicitly when block semantic checks are needed.
    ///
    /// Section Header and Interface Description raw blocks are decoded before writing.
    /// Their representations and individual options must be valid in either mode.
    /// If decoding fails, nothing is written and the writer state is unchanged.
    /// The state is updated after a successful write.
    ///
    /// # Errors
    /// Correct validation or encoding failures and retry with the writer state unchanged.
    /// If an I/O error occurs, discard or repair any partially written block.
    pub fn write_raw_block(&mut self, raw_block: &RawBlock) -> Result<usize, PcapNgWriteError> {
        // The order of operation is important to prevent writing invalid files in case of error.
        // The state is updated only after a successful write.
        // The endianness is determined before the write to handle endianness changes when a new SectionHeader is encountered in the block list.
        raw_block.validate()?;
        let opt_block = self.state.decode_block_if_needed(raw_block, false)?;
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
    /// Bytes written directly must preserve block framing and the current section state.
    /// Flush buffered output through this reference when needed.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Access the current [`PcapNgState`].
    pub fn state(&self) -> &PcapNgState {
        &self.state
    }
}
