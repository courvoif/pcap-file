//! This module contains informations relative to the global Pcap header.

use std::io::Read;

use byteorder::*;

use errors::*;

/// Struct that represent the global Pcap header of a Pcap file
#[derive(Copy, Clone, Debug)]
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

    /// Datalink type (first layer in the packet (u32))
    pub datalink: Datalink
}


impl PcapHeader {

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
    ///     datalink : datalink
    /// };
    /// ```
    pub fn with_datalink(datalink: Datalink) -> PcapHeader {

        PcapHeader {
            magic_number: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: datalink
        }
    }

    /// Parse a `Reader` and create a new PcapHeader from it if possible
    pub fn from_reader<R: Read>(reader: &mut R) -> ResultChain<PcapHeader> {

        let magic_number = reader.read_u32::<BigEndian>()?;

        match magic_number {

            0xa1b2c3d4 | 0xa1b23c4d => return init_pcap_header::<_, BigEndian>(reader, magic_number),
            0xd4c3b2a1 | 0x4d3cb2a1 => return init_pcap_header::<_, LittleEndian>(reader, magic_number),
            _ => bail!(ErrorKind::BadMagicNumber(magic_number))
        };

        // Inner function used for the initialisation of the `PcapHeader`
        fn init_pcap_header<R: ReadBytesExt, B: ByteOrder>(reader: &mut R, magic_number:u32) -> Result<PcapHeader, Error> {

            Ok(
                PcapHeader {

                    magic_number : magic_number,
                    version_major : reader.read_u16::<B>()?,
                    version_minor : reader.read_u16::<B>()?,
                    ts_correction : reader.read_i32::<B>()?,
                    ts_accuracy : reader.read_u32::<B>()?,
                    snaplen : reader.read_u32::<B>()?,
                    datalink : Datalink::from(reader.read_u32::<B>()?)
                }
            )
        }
    }

    /// Convert the `PcapHeader` to a slice of bytes.
    pub fn to_array<B: ByteOrder>(&self) -> ResultChain<Vec<u8>> {

        let mut out = Vec::with_capacity(24);

        //The magic number is always read in BigEndian so it's always written in BigEndian too
        out.write_u32::<BigEndian>(self.magic_number)?;
        out.write_u16::<B>(self.version_major)?;
        out.write_u16::<B>(self.version_minor)?;
        out.write_i32::<B>(self.ts_correction)?;
        out.write_u32::<B>(self.ts_accuracy)?;
        out.write_u32::<B>(self.snaplen)?;
        out.write_u32::<B>(self.datalink.into())?;

        Ok(out)
    }

    /// Return the endianness of the global header
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

    /// Return the timestamp resolution of the global header
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
}

/// Represents the endianness of the global header
#[derive(Copy, Clone, Debug)]
pub enum Endianness {
    Big,
    Little
}

/// Represents each possible timestamp resolution
#[derive(Copy, Clone, Debug)]
pub enum TsResolution {
    MicroSecond,
    NanoSecond
}

/// Represents each possible Pcap datalink
#[derive(Copy, Clone, Debug)]
pub enum Datalink {

    Ethernet,
    RawIP,
    Unknown(u32)
}

impl From<u32> for Datalink {

    fn from(link: u32) -> Datalink {

        match link {

            1 => Datalink::Ethernet,
            101 => Datalink::RawIP,
            t => Datalink::Unknown(t)
        }
    }
}

impl From<Datalink> for u32 {

    fn from(link: Datalink) -> u32 {

        match link {
            Datalink::Ethernet => 1,
            Datalink::RawIP => 101,
            Datalink::Unknown(t) => t
        }
    }
}