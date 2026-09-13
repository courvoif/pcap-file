//! Pcap global-header parsing and writing.

use std::io::Write;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use crate::pcap::PcapTsResolution;
use crate::pcap::errors::{PcapParseError, PcapValidationError, PcapWriteError};
use crate::{DataLink, Endianness};

/// Global header of a pcap file.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PcapHeader {
    /// Major format version.
    pub version_major: u16,

    /// Minor format version.
    pub version_minor: u16,

    /// GMT-to-local-time correction; should always be 0.
    pub ts_correction: i32,

    /// Timestamp accuracy; should always be 0.
    pub ts_accuracy: u32,

    /// Maximum number of bytes captured from each packet.
    pub snaplen: u32,

    /// Link-layer protocol of captured packets.
    pub datalink: DataLink,

    /// Resolution of packet timestamps.
    pub ts_resolution: PcapTsResolution,

    /// Byte order of pcap metadata, excluding packet data.
    pub endianness: Endianness,
}

impl PcapHeader {
    /// Parses a [`PcapHeader`] from a byte slice.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapParseError::IncompleteBuffer`] if the input does not
    ///   contain a complete header.
    /// - Returns [`PcapParseError::Validation`] if the header is invalid.
    pub fn from_slice(mut slice: &[u8]) -> Result<(&[u8], PcapHeader), PcapParseError> {
        // Check that slice.len() > PcapHeader length
        if slice.len() < 24 {
            return Err(PcapParseError::IncompleteBuffer(24, slice.len()));
        }

        let magic_number = slice.read_u32::<BigEndian>().unwrap();

        match magic_number {
            0xA1B2C3D4 => return init_pcap_header::<BigEndian>(slice, PcapTsResolution::Microsecond, Endianness::Big),
            0xA1B23C4D => return init_pcap_header::<BigEndian>(slice, PcapTsResolution::Nanosecond, Endianness::Big),
            0xD4C3B2A1 => {
                return init_pcap_header::<LittleEndian>(slice, PcapTsResolution::Microsecond, Endianness::Little);
            }
            0x4D3CB2A1 => {
                return init_pcap_header::<LittleEndian>(slice, PcapTsResolution::Nanosecond, Endianness::Little);
            }
            _ => return Err(PcapValidationError::InvalidMagicNumber(magic_number).into()),
        };

        // Inner function used for the initialisation of the PcapHeader.
        // Must check the src length before calling it.
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
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// - Returns an error if the header cannot be written.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<usize, PcapWriteError> {
        return match self.endianness {
            Endianness::Big => write_header::<_, BigEndian>(self, writer),
            Endianness::Little => write_header::<_, LittleEndian>(self, writer),
        };

        fn write_header<W: Write, B: ByteOrder>(header: &PcapHeader, writer: &mut W) -> Result<usize, PcapWriteError> {
            let magic_number = match header.ts_resolution {
                PcapTsResolution::Microsecond => 0xA1B2C3D4,
                PcapTsResolution::Nanosecond => 0xA1B23C4D,
            };

            writer.write_u32::<B>(magic_number)?;
            writer.write_u16::<B>(header.version_major)?;
            writer.write_u16::<B>(header.version_minor)?;
            writer.write_i32::<B>(header.ts_correction)?;
            writer.write_u32::<B>(header.ts_accuracy)?;
            writer.write_u32::<B>(header.snaplen)?;
            writer.write_u32::<B>(header.datalink.into())?;

            Ok(24)
        }
    }
}

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
///     ts_resolution: PcapTsResolution::Microsecond,
///     endianness: Endianness::native()
/// };
/// ```
impl Default for PcapHeader {
    fn default() -> Self {
        PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: DataLink::ETHERNET,
            ts_resolution: PcapTsResolution::Microsecond,
            endianness: Endianness::default(),
        }
    }
}
