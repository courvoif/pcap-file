use std::io::Write;

use thiserror::Error;

use crate::pcapng::{InterfaceDescriptionBlock, SectionHeaderBlock, PcapNgBlock, ParsedBlock};
use byteorder::{ByteOrder, NativeEndian, BigEndian, LittleEndian};
use crate::Endianness;


/// Wraps a writer and uses it to write a PcapNg.
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
/// use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// let mut out = Vec::new();
/// let mut pcapng_writer = PcapNgWriter::new(out).unwrap();
///
/// // Read test.pcapng
/// for block in pcapng_reader {
///
///     //Check if there is no error
///     let block = block.unwrap();
///
///     //Parse block content
///     let parsed_block = block.parsed().unwrap();
///
///     //Write parsed Block
///     pcapng_writer.write_parsed_block(&parsed_block).unwrap();
/// }
/// ```
pub struct PcapNgWriter<W: Write> {
    section: SectionHeaderBlock<'static>,
    interfaces: Vec<InterfaceDescriptionBlock<'static>>,
    writer: W
}

impl<W: Write> PcapNgWriter<W> {

    pub fn new(writer: W) -> PcapWriteResult<Self> {

        let tmp = NativeEndian::read_u16(&[0x42, 0x00]);

        let endianness = match tmp {
            0x4200 => Endianness::Big,
            0x0042 => Endianness::Little,
            _ => unreachable!()
        };

        Self::with_endianness(writer, endianness)
    }

    pub fn with_endianness(writer: W, endianness: Endianness) -> PcapWriteResult<Self> {

        let mut section = SectionHeaderBlock::new();
        section.set_endianness(endianness);

        Self::with_section_header(writer, &section)
    }

    pub fn with_section_header(mut writer: W,  section: &SectionHeaderBlock) -> PcapWriteResult<Self> {

        match section.endianness() {
            Endianness::Big => section.write_block_to::<BigEndian, _>(&mut writer)?,
            Endianness::Little => section.write_block_to::<LittleEndian, _>(&mut writer)?,
        };

        Ok(
            Self {
                section: section.clone().into_owned(),
                interfaces: vec![],
                writer,
            }
        )
    }

    pub fn write_block(&mut self, block: &ParsedBlock) -> PcapWriteResult<usize> {

        match self.section.endianness() {
            Endianness::Big => self.write_block_inner::<BigEndian>(block),
            Endianness::Little => self.write_block_inner::<LittleEndian>(block),
        }
    }

    fn write_block_inner<B: ByteOrder>(&mut self, block: &ParsedBlock) -> PcapWriteResult<usize> {

        match block {

            ParsedBlock::SectionHeader(a) => {

                self.section = a.clone().into_owned();
                self.interfaces.clear();
                match self.section.endianness() {
                    Endianness::Big => Ok(a.write_block_to::<BigEndian, _>(&mut self.writer)?),
                    Endianness::Little => Ok(a.write_block_to::<LittleEndian, _>(&mut self.writer)?),
                }
            },
            ParsedBlock::InterfaceDescription(a) => {

                self.interfaces.push(a.clone().into_owned());
                Ok(a.write_block_to::<B, _>(&mut self.writer)?)
            },
            ParsedBlock::Packet(a) => {
                Ok(a.write_block_to::<B, _>(&mut self.writer)?)
            },
            ParsedBlock::SimplePacket(a) => {
                Ok(a.write_block_to::<B, _>(&mut self.writer)?)
            },
            ParsedBlock::NameResolution(a) => {
                Ok(a.write_block_to::<B, _>(&mut self.writer)?)
            },
            ParsedBlock::InterfaceStatistics(a) => {

                if a.interface_id as usize >= self.interfaces.len() {
                    Err(PcapWriteError::InvalidInterfaceId(a.interface_id))
                }
                else {
                    Ok(a.write_block_to::<B, _>(&mut self.writer)?)
                }
            },
            ParsedBlock::EnhancedPacket(a) => {
                if a.interface_id as usize >= self.interfaces.len() {
                    Err(PcapWriteError::InvalidInterfaceId(a.interface_id))
                }
                else {
                    Ok(a.write_block_to::<B, _>(&mut self.writer)?)
                }
            },
            ParsedBlock::SystemdJournalExport(a) => {
                Ok(a.write_block_to::<B, _>(&mut self.writer)?)
            },
            ParsedBlock::Unknown(a) => {
                Ok(a.write_block_to::<B, _>(&mut self.writer)?)
            },
        }
    }

    /// Consumes the `PcapNgWriter`, returning the wrapped writer.
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Gets a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
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

    #[error("The file doesn't have a Section Header yet")]
    NoSectionHeader,

    #[error("The endianness of this block is different than the one of the current section")]
    WrongBlockEndianness,
}

impl From<std::io::Error> for PcapWriteError {
    fn from(err: std::io::Error) -> Self {
        PcapWriteError::Io(err)
    }
}