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

    /// LINKTYPE code identifying the first layer in the packet.
    pub datalink: DataLink,

    /// Upper 16 bits of the link-type word, preserved unchanged.
    /// Bit 10 indicates that bits 12–15 specify the FCS length in 16-bit words.
    /// Set to `0` when no additional information is supplied.
    pub additional_info: u16,

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
            let version_major = src.read_u16::<B>().unwrap();
            let version_minor = src.read_u16::<B>().unwrap();
            let ts_correction = src.read_i32::<B>().unwrap();
            let ts_accuracy = src.read_u32::<B>().unwrap();
            let snaplen = src.read_u32::<B>().unwrap();
            let linktype_info = src.read_u32::<B>().unwrap();

            let header = PcapHeader {
                version_major,
                version_minor,
                ts_correction,
                ts_accuracy,
                snaplen,
                datalink: DataLink::from(linktype_info & 0xFFFF),
                additional_info: (linktype_info >> 16) as u16,
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
    /// Use a LINKTYPE code that fits in 16 bits; otherwise no bytes are written.
    /// An I/O failure can leave a partial global header in the output.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<usize, PcapWriteError> {
        return match self.endianness {
            Endianness::Big => write_header::<BigEndian, _>(self, writer),
            Endianness::Little => write_header::<LittleEndian, _>(self, writer),
        };

        /// Writes the global header using the selected byte order.
        fn write_header<B: ByteOrder, W: Write>(header: &PcapHeader, writer: &mut W) -> Result<usize, PcapWriteError> {
            let datalink = u16::try_from(u32::from(header.datalink))
                .map_err(|_| PcapValidationError::InvalidLinkType(header.datalink))?;
            let linktype_info = u32::from(datalink) | (u32::from(header.additional_info) << 16);

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
                .write_u32::<B>(linktype_info)
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
///     additional_info: 0,
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
            additional_info: 0,
            ts_resolution: PcapTsResolution::MicroSecond,
            endianness: Endianness::default(),
        }
    }
}

/* ----- Tests ----- */

/// Checks global header metadata decoding and encoding limits.
#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use super::*;
    use crate::pcap::PcapWriter;

    /* ----- Link-type metadata ----- */

    /// Checks that LINKTYPE and metadata decode independently and preserve the wire bytes.
    #[test]
    fn linktype_metadata_roundtrip() {
        for (prefix, endianness, ts_resolution) in [
            (
                "a1b2c3d40002000400000000000000000000ffff",
                Endianness::Big,
                PcapTsResolution::MicroSecond,
            ),
            (
                "a1b23c4d0002000400000000000000000000ffff",
                Endianness::Big,
                PcapTsResolution::NanoSecond,
            ),
            (
                "d4c3b2a1020004000000000000000000ffff0000",
                Endianness::Little,
                PcapTsResolution::MicroSecond,
            ),
            (
                "4d3cb2a1020004000000000000000000ffff0000",
                Endianness::Little,
                PcapTsResolution::NanoSecond,
            ),
        ] {
            for (word, datalink, additional_info) in [
                (0x0000_0001u32, DataLink::ETHERNET, 0),
                (0x2400_0001, DataLink::ETHERNET, 0x2400),
                (0x0400_0001, DataLink::ETHERNET, 0x0400),
                (0x2000_0001, DataLink::ETHERNET, 0x2000),
                (0xF400_0001, DataLink::ETHERNET, 0xF400),
                (0x0800_0000, DataLink::NULL, 0x0800),
                (0xFFFF_FFFF, DataLink::Unknown(0xFFFF), 0xFFFF),
            ] {
                let mut input = hex::decode(prefix).unwrap();
                input.extend_from_slice(&match endianness {
                    Endianness::Big => word.to_be_bytes(),
                    Endianness::Little => word.to_le_bytes(),
                });
                input.extend_from_slice(&[0xAA, 0xBB]);

                let (remaining, header) = PcapHeader::from_slice(&input).unwrap();
                assert_eq!(remaining, &[0xAA, 0xBB]);
                assert_eq!(header.datalink, datalink);
                assert_eq!(header.additional_info, additional_info);
                assert_eq!(header.endianness, endianness);
                assert_eq!(header.ts_resolution, ts_resolution);

                let mut output = Vec::new();
                assert_eq!(header.write_to(&mut output).unwrap(), 24);
                assert_eq!(output, input[..24]);
            }
        }
    }

    /// Checks that oversized LINKTYPE codes fail before either writing entry point emits bytes.
    #[test]
    fn invalid_linktype_leaves_output_unchanged() {
        for endianness in [Endianness::Big, Endianness::Little] {
            for code in [0x1_0000, 0x2400_0001, u32::MAX] {
                let header = PcapHeader {
                    datalink: DataLink::Unknown(code),
                    additional_info: 0x2400,
                    endianness,
                    ..Default::default()
                };
                let mut output = vec![0xAA, 0xBB];

                assert!(matches!(
                    header.write_to(&mut output),
                    Err(PcapWriteError::Validation(PcapValidationError::InvalidLinkType(DataLink::Unknown(value))))
                        if value == code
                ));
                assert_eq!(output, [0xAA, 0xBB]);

                assert!(matches!(
                    PcapWriter::with_header(&mut output, header),
                    Err(PcapWriteError::Validation(PcapValidationError::InvalidLinkType(DataLink::Unknown(value))))
                        if value == code
                ));
                assert_eq!(output, [0xAA, 0xBB]);
            }
        }
    }
}
