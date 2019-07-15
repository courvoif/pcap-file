//! This module contains the `PcapHeader` struct which represents a global pcap header.

use crate::errors::*;

use std::io::Write;
use std::io::Read;
use byteorder::{BigEndian, LittleEndian, ByteOrder, WriteBytesExt, ReadBytesExt};

use crate::{DataLink, Endianness, TsResolution};


/// Pcap Global Header
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PcapHeader {

    /// Magic number
    pub magic_number: u32,

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
    pub datalink: DataLink
}

impl PcapHeader {

    /// Creates a new `PcapHeader` from a reader
    ///
    /// Returns an error if the reader doesn't contain a valid pcap
    /// or if there is a reading error.
    pub fn from_reader<R: Read>(reader: &mut R) -> ResultParsing<PcapHeader> {

        let magic_number = reader.read_u32::<BigEndian>()?;

        match magic_number {

            0xa1b2c3d4 | 0xa1b23c4d => return init_pcap_header::<_, BigEndian>(reader, magic_number),
            0xd4c3b2a1 | 0x4d3cb2a1 => return init_pcap_header::<_, LittleEndian>(reader, magic_number),
            _ => return Err(PcapError::InvalidField("PcapHeader wrong magic number"))
        };

        // Inner function used for the initialisation of the `PcapHeader`
        fn init_pcap_header<R: Read, B: ByteOrder>(reader: &mut R, magic_number:u32) -> ResultParsing<PcapHeader> {

            Ok(
                PcapHeader {

                    magic_number,
                    version_major : reader.read_u16::<B>()?,
                    version_minor : reader.read_u16::<B>()?,
                    ts_correction : reader.read_i32::<B>()?,
                    ts_accuracy : reader.read_u32::<B>()?,
                    snaplen : reader.read_u32::<B>()?,
                    datalink : DataLink::from(reader.read_u32::<B>()?)
                }
            )
        }
    }

    /// Creates a new `PcapHeader` from a slice of bytes
     ///
     /// Returns an error if the reader doesn't contain a valid pcap
     /// or if there is a reading error.
     ///
     /// `PcapError::IncompleteBuffer` indicates that there is not enough data in the buffer
    pub fn from_slice(mut slice: &[u8]) -> ResultParsing<(PcapHeader, &[u8])> {

        if slice.len() < 24 {
            return Err(PcapError::IncompleteBuffer(24 - slice.len()))
        }

        let header = PcapHeader::from_reader(&mut slice)?;

        Ok((header, slice))
    }

    /// Set the timestamp resolution to ts_resolution by modifying the magic_number
    /// Preserve its endianness
    pub fn set_ts_resolution(&mut self, ts_resolution: TsResolution) {
        use TsResolution::*;

        let mut new_magic: u32 = match ts_resolution {
            MicroSecond => 0xa1b2c3d4,
            NanoSecond => 0xa1b23c4d,
        };

        if self.endianness().is_little() {
            new_magic = new_magic.swap_bytes();
        }

        self.magic_number = new_magic;
    }

    /// Change the endianness of the magic_number
    pub fn set_endianness(&mut self, endianness: Endianness) {

        if self.endianness() != endianness {
            self.magic_number = self.magic_number.swap_bytes();
        }
    }

    /// Write a `PcapHeader` to a writer.
    ///
    /// Writes 24o in the writer on success.
    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W) -> ResultParsing<()> {

        //The magic number is always read in BigEndian so it's always written in BigEndian too
        writer.write_u32::<BigEndian>(self.magic_number)?;
        writer.write_u16::<B>(self.version_major)?;
        writer.write_u16::<B>(self.version_minor)?;
        writer.write_i32::<B>(self.ts_correction)?;
        writer.write_u32::<B>(self.ts_accuracy)?;
        writer.write_u32::<B>(self.snaplen)?;
        writer.write_u32::<B>(self.datalink.into())?;

        Ok(())
    }

    /// Return the endianness of the pcap
    ///
    /// # Panics
    ///
    /// Panics if the magic number is invalid
    pub fn endianness(&self) -> Endianness {

        match self.magic_number {

            0xa1b2c3d4 | 0xa1b23c4d => Endianness::Big,
            0xd4c3b2a1 | 0x4d3cb2a1 => Endianness::Little,
            _ => unreachable!("Wrong magic number, can't get the header's endianness")
        }
    }

    /// Return the timestamp resolution of the pcap
    ///
    /// # Panics
    ///
    /// Panics if the magic number is invalid
    pub fn ts_resolution(&self) -> TsResolution {

        match self.magic_number {

            0xa1b2c3d4 | 0xd4c3b2a1 => TsResolution::MicroSecond,
            0xa1b23c4d | 0x4d3cb2a1 => TsResolution::NanoSecond,
            _ => unreachable!("Wrong magic number, can't get the header's timestamp resolution")
        }
    }

    ///////// Deprecated /////////

    /// Convert a `PcapHeader` to a `Vec<u8>`.
    #[deprecated(since="1.0.0", note="Please use `write_to` instead")]
    pub fn to_array<B: ByteOrder>(&self) -> ResultParsing<Vec<u8>> {

        let mut out = Vec::with_capacity(24);

        self.write_to::<_, B>(&mut out)?;

        Ok(out)
    }

    /// Creates a new `PcapHeader` with the following parameters:
    ///
    /// ```rust,ignore
    /// PcapHeader {
    ///
    ///     magic_number : 0xa1b2c3d4,
    ///     version_major : 2,
    ///     version_minor : 4,
    ///     ts_correction : 0,
    ///     ts_accuracy : 0,
    ///     snaplen : 65535,
    ///     datalink : #datalink
    /// };
    /// ```
    #[deprecated(since="1.0.0", note="Please use the Default struct constructor instead, will be removed in 1.0")]
    pub fn with_datalink(datalink: DataLink) -> PcapHeader {

        PcapHeader {
            datalink,
            ..Default::default()
        }
    }
}

/// Creates a new `PcapHeader` with the default parameters:
///
/// ```rust,ignore
/// PcapHeader {
///
///     magic_number : 0xa1b2c3d4,
///     version_major : 2,
///     version_minor : 4,
///     ts_correction : 0,
///     ts_accuracy : 0,
///     snaplen : 65535,
///     datalink : DataLink::ETHERNET
/// };
/// ```
impl Default for PcapHeader {
    fn default() -> Self {
        PcapHeader {
            magic_number: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: DataLink::ETHERNET,
        }
    }
}

