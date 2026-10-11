//! Classic pcap global header decoding and encoding.

/* ----- Imports ----- */

use std::io::Write;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use crate::pcap::{PcapParseError, PcapTsResolution, PcapValidationError, PcapWriteError};
use crate::{DataLink, Endianness};

/* ----- Global header ----- */

/// Pcap Global Header
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PcapHeader {
    /// Major version number
    pub version_major: u16,

    /// Minor version number
    pub version_minor: u16,

    /// GMT to local timezone correction, should always be 0
    pub ts_correction: i32,

    /// Timestamp accuracy, should always be 0
    pub ts_accuracy: u32,

    /// Max length of captured packet, typically 65535
    pub snaplen: u32,

    /// DataLink type (first layer in the packet)
    pub datalink: DataLink,

    /// Timestamp resolution of the pcap (microsecond or nanosecond)
    pub ts_resolution: PcapTsResolution,

    /// Endianness of the pcap (excluding the packet data)
    pub endianness: Endianness,
}

impl PcapHeader {
    /// Returns the global header and the remaining input after its 24 bytes.
    /// The magic number selects byte order and timestamp resolution.
    /// Other header fields are preserved without semantic validation.
    ///
    /// # Errors
    /// Supply the complete header on [`PcapParseError::IncompleteBuffer`].
    /// A rejected magic number means the input is not a supported classic pcap header.
    pub fn from_slice(mut slice: &[u8]) -> Result<(&[u8], PcapHeader), PcapParseError> {
        // The complete global header must be available before decoding its fields.
        if slice.len() < 24 {
            return Err(PcapParseError::IncompleteBuffer(24, slice.len()));
        }

        let magic_number = slice.read_u32::<BigEndian>().unwrap();

        match magic_number {
            0xA1B2C3D4 => return init_pcap_header::<BigEndian>(slice, PcapTsResolution::MicroSecond, Endianness::Big),
            0xA1B23C4D => return init_pcap_header::<BigEndian>(slice, PcapTsResolution::NanoSecond, Endianness::Big),
            0xD4C3B2A1 => {
                return init_pcap_header::<LittleEndian>(slice, PcapTsResolution::MicroSecond, Endianness::Little);
            }
            0x4D3CB2A1 => {
                return init_pcap_header::<LittleEndian>(slice, PcapTsResolution::NanoSecond, Endianness::Little);
            }
            _ => return Err(PcapValidationError::InvalidMagicNumber(magic_number).into()),
        };

        // Inner function used for the initialisation of the PcapHeader.
        // Must check the src length before calling it.
        /// Decodes the fields following a validated global header magic number.
        fn init_pcap_header<B: ByteOrder>(
            mut src: &[u8],
            ts_resolution: PcapTsResolution,
            endianness: Endianness,
        ) -> Result<(&[u8], PcapHeader), PcapParseError> {
            let header = PcapHeader {
                version_major: src.read_u16::<B>().unwrap(),
                version_minor: src.read_u16::<B>().unwrap(),
                ts_correction: src.read_i32::<B>().unwrap(),
                ts_accuracy: src.read_u32::<B>().unwrap(),
                snaplen: src.read_u32::<B>().unwrap(),
                datalink: DataLink::from(src.read_u32::<B>().unwrap()),
                ts_resolution,
                endianness,
            };

            Ok((src, header))
        }
    }

    /// Writes a [`PcapHeader`] to a writer.
    ///
    /// Uses the byte order and timestamp resolution stored in the header.
    ///
    /// # Errors
    /// An I/O failure can leave a partial global header in the output.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<usize, PcapWriteError> {
        return match self.endianness {
            Endianness::Big => write_header::<_, BigEndian>(self, writer),
            Endianness::Little => write_header::<_, LittleEndian>(self, writer),
        };

        /// Writes the global header using the selected byte order.
        fn write_header<W: Write, B: ByteOrder>(header: &PcapHeader, writer: &mut W) -> Result<usize, PcapWriteError> {
            let magic_number = match header.ts_resolution {
                PcapTsResolution::MicroSecond => 0xA1B2C3D4,
                PcapTsResolution::NanoSecond => 0xA1B23C4D,
            };

            writer
                .write_u32::<B>(magic_number)
                .map_err(|e| PcapWriteError::FieldWriteFailed("magic_number", e))?;
            writer
                .write_u16::<B>(header.version_major)
                .map_err(|e| PcapWriteError::FieldWriteFailed("version_major", e))?;
            writer
                .write_u16::<B>(header.version_minor)
                .map_err(|e| PcapWriteError::FieldWriteFailed("version_minor", e))?;
            writer
                .write_i32::<B>(header.ts_correction)
                .map_err(|e| PcapWriteError::FieldWriteFailed("ts_correction", e))?;
            writer
                .write_u32::<B>(header.ts_accuracy)
                .map_err(|e| PcapWriteError::FieldWriteFailed("ts_accuracy", e))?;
            writer
                .write_u32::<B>(header.snaplen)
                .map_err(|e| PcapWriteError::FieldWriteFailed("snaplen", e))?;
            writer
                .write_u32::<B>(header.datalink.into())
                .map_err(|e| PcapWriteError::FieldWriteFailed("datalink", e))?;

            Ok(24)
        }
    }
}

/* ----- Default header ----- */

/// Creates a new [`PcapHeader`] with these parameters:
///
/// ```rust
/// use pcap_file::{DataLink, Endianness};
/// use pcap_file::pcap::{PcapHeader, PcapTsResolution};
///
/// let header = PcapHeader {
///     version_major: 2,
///     version_minor: 4,
///     ts_correction: 0,
///     ts_accuracy: 0,
///     snaplen: 65535,
///     datalink: DataLink::ETHERNET,
///     ts_resolution: PcapTsResolution::MicroSecond,
///     endianness: Endianness::native()
/// };
/// ```
impl Default for PcapHeader {
    /// Returns the default capture settings.
    fn default() -> Self {
        PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: DataLink::ETHERNET,
            ts_resolution: PcapTsResolution::MicroSecond,
            endianness: Endianness::default(),
        }
    }
}
