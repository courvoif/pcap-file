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

    /// GMT to local timezone correction
    pub ts_correction: i32,

    /// Timestamp accuracy
    pub ts_accuracy: u32,

    /// Max length of captured packet
    pub snaplen: u32,

    /// Datalink type (first layer in the packet (u32))
    pub datalink: Datalink
}


impl PcapHeader {

    pub fn from_reader<R: Read>(reader: &mut R) -> ResultChain<PcapHeader> {

        let magic_number = reader.read_u32::<BigEndian>()?;

        match magic_number {

            0xa1b2c3d4 => return init_pcap_header::<_, BigEndian>(reader, magic_number),
            0xd4c3b2a1 => return init_pcap_header::<_, LittleEndian>(reader, magic_number),
            _ => bail!(ErrorKind::BadMagicNumber(magic_number))
        };

        // Inner function used for the initialisation of the `PcapHeader`
        fn init_pcap_header<R: ReadBytesExt, B: ByteOrder>(reader: &mut R, magic_number:u32) -> Result<PcapHeader, Error>{

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