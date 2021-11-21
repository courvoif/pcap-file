use std::io::Write;

use thiserror::Error;

use crate::pcapng::{InterfaceDescriptionBlock, SectionHeaderBlock, PcapNgBlock, Block};
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

        let mut section = SectionHeaderBlock::default();
        section.set_endianness(endianness);

        Self::with_section_header(writer, section)
    }

    pub fn with_section_header(mut writer: W, section: SectionHeaderBlock<'static>) -> PcapWriteResult<Self> {
        match section.endianness() {
            Endianness::Big => section.clone().into_block().write_to::<BigEndian, _>(&mut writer)?,
            Endianness::Little => section.clone().into_block().write_to::<LittleEndian, _>(&mut writer)?,
        };

        Ok(
            Self {
                section,
                interfaces: vec![],
                writer,
            }
        )
    }

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

            _ => ()
        }

        match self.section.endianness() {
            Endianness::Big => block.write_to::<BigEndian, _>(&mut self.writer).map_err(|e| e.into()),
            Endianness::Little => block.write_to::<LittleEndian, _>(&mut self.writer).map_err(|e| e.into())
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
    InvalidInterfaceId(u32)
}

impl From<std::io::Error> for PcapWriteError {
    fn from(err: std::io::Error) -> Self {
        PcapWriteError::Io(err)
    }
}