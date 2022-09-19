use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};
use thiserror::Error;

use crate::pcapng::{Block, InterfaceDescriptionBlock, PcapNgBlock, SectionHeaderBlock};
use crate::Endianness;


/// Writes a PcapNg to a writer.
///
/// # Examples
///
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
    section: SectionHeaderBlock<'static>,
    interfaces: Vec<InterfaceDescriptionBlock<'static>>,
    writer: W,
}

impl<W: Write> PcapNgWriter<W> {
    /// Creates a new `PcapNgWriter` from an existing writer.
    /// Defaults to the native endianness of the CPU.
    ///
    /// Writes this global pcap header to the file:
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
    /// # Errors
    ///
    /// Return an error if the writer can't be written to.
    ///
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::fs::File;
    ///
    /// use pcap_file::pcap::PcapWriter;
    ///
    /// let file_out = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_writer = PcapWriter::new(file_out);
    /// ```
    pub fn new(writer: W) -> PcapWriteResult<Self> {
        // Get endianness of the current processor
        #[cfg(target_endian = "big")]
        let endianness = Endianness::Big;

        #[cfg(target_endian = "little")]
        let endianness = Endianness::Little;

        Self::with_endianness(writer, endianness)
    }

    /// Creates a new `PcapNgWriter` from an existing writer with the given endianness
    pub fn with_endianness(writer: W, endianness: Endianness) -> PcapWriteResult<Self> {
        let section = SectionHeaderBlock { endianness, ..Default::default() };

        Self::with_section_header(writer, section)
    }

    /// Creates a new `PcapNgWriter` from an existing writer with the given section header
    pub fn with_section_header(mut writer: W, section: SectionHeaderBlock<'static>) -> PcapWriteResult<Self> {
        match section.endianness {
            Endianness::Big => section.clone().into_block().write_to::<BigEndian, _>(&mut writer)?,
            Endianness::Little => section.clone().into_block().write_to::<LittleEndian, _>(&mut writer)?,
        };

        Ok(Self { section, interfaces: vec![], writer })
    }

    /// Writes a `Block`.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
    /// use std::time::Duration;
    ///
    /// use pcap_file::pcapng::{
    ///     EnhancedPacketBlock, InterfaceDescriptionBlock, PcapNgBlock, PcapNgWriter,
    /// };
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
    /// let packet = EnhancedPacketBlock {
    ///     interface_id: 0,
    ///     timestamp: Duration::from_secs(0),
    ///     original_len: data.len() as u32,
    ///     data: Cow::Borrowed(&data),
    ///     options: vec![],
    /// };
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    ///
    /// pcap_ng_writer.write_block(&interface.into_block()).unwrap();
    /// pcap_ng_writer.write_block(&packet.into_block()).unwrap();
    /// ```
    pub fn write_block(&mut self, block: &Block) -> PcapWriteResult<usize> {
        match block {
            Block::SectionHeader(a) => {
                self.section = a.clone().into_owned();
                self.interfaces.clear();
            },
            Block::InterfaceDescription(a) => {
                self.interfaces.push(a.clone().into_owned());
            },
            Block::InterfaceStatistics(a) => {
                if a.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapWriteError::InvalidInterfaceId(a.interface_id));
                }
            },
            Block::EnhancedPacket(a) => {
                if a.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapWriteError::InvalidInterfaceId(a.interface_id));
                }
            },

            _ => (),
        }

        match self.section.endianness {
            Endianness::Big => block.write_to::<BigEndian, _>(&mut self.writer).map_err(|e| e.into()),
            Endianness::Little => block.write_to::<LittleEndian, _>(&mut self.writer).map_err(|e| e.into()),
        }
    }

    /// Consumes the `PcapNgWriter`, returning the wrapped writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Gets a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// You should not be used unless you really know what you're doing
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}


pub type PcapWriteResult<T> = Result<T, PcapWriteError>;

#[derive(Error, Debug)]
pub enum PcapWriteError {
    #[error("Io error")]
    Io(#[source] std::io::Error),

    #[error("No corresponding interface id: {0}")]
    InvalidInterfaceId(u32),
}

impl From<std::io::Error> for PcapWriteError {
    fn from(err: std::io::Error) -> Self {
        PcapWriteError::Io(err)
    }
}
