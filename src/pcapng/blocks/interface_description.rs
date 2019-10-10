use crate::pcapng::blocks::common::opts_from_slice;
use crate::errors::PcapError;
use crate::DataLink;
use byteorder::{ByteOrder, ReadBytesExt};

/// An Interface Description Block (IDB) is the container for information describing an interface
/// on which packet data is captured.
#[derive(Clone, Debug)]
pub struct InterfaceDescriptionBlock<'a> {

    /// A value that defines the link layer type of this interface.
    /// The list of Standardized Link Layer Type codes is available in the
    /// [tcpdump.org link-layer header types registry.](http://www.tcpdump.org/linktypes.html).
    pub linktype: DataLink,

    /// Not used - MUST be filled with 0 by pcap file writers, and MUST be ignored by pcapng file readers.
    pub reserved: u16,

    /// Maximum number of octets captured from each packet.
    /// The portion of each packet that exceeds this value will not be stored in the file.
    /// A value of zero indicates no limit.
    pub snaplen: u32,

    /// Options
    pub options: Vec<InterfaceDescriptionOption<'a>>
}

impl<'a> InterfaceDescriptionBlock<'a> {

    pub fn from_slice<B:ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {

        if slice.len() < 12 {
            return Err(PcapError::InvalidField("InterfaceDescriptionBlock: block length < 8"));
        }

        let linktype = (slice.read_u16::<B>()? as u32).into();
        let reserved = slice.read_u16::<B>()?;
        let snaplen = slice.read_u32::<B>()?;
        let (slice, options) = InterfaceDescriptionOption::from_slice::<B>(slice)?;

        let block = InterfaceDescriptionBlock {
            linktype,
            reserved,
            snaplen,
            options
        };

        Ok((slice, block))
    }
}

#[derive(Clone, Debug)]
pub enum InterfaceDescriptionOption<'a> {

    Comment(&'a str),

    /// The if_name option is a UTF-8 string containing the name of the device used to capture data.
    IfName(&'a str),

    /// The if_description option is a UTF-8 string containing the description of the device used to capture data.
    IfDescription(&'a str),

    /// The if_IPv4addr option is an IPv4 network address and corresponding netmask for the interface.
    IfIpv4Addr(&'a [u8]),

    /// The if_IPv6addr option is an IPv6 network address and corresponding prefix length for the interface.
    IfIpv6Addr(&'a [u8]),

    /// The if_MACaddr option is the Interface Hardware MAC address (48 bits), if available.
    IfMacAddr(&'a [u8]),

    /// The if_EUIaddr option is the Interface Hardware EUI address (64 bits), if available.
    IfEulAddr(u64),

    /// The if_speed option is a 64-bit number for the Interface speed (in bits per second).
    IfSpeed(u64),

    /// The if_tsresol option identifies the resolution of timestamps.
    IfTsResol(u8),

    /// The if_tzone option identifies the time zone for GMT support.
    IfTzone(u32),

    /// The if_filter option identifies the filter (e.g. "capture only TCP traffic") used to capture traffic.
    IfFilter(&'a [u8]),

    /// The if_os option is a UTF-8 string containing the name of the operating system
    /// of the machine in which this interface is installed.
    IfOs(&'a str),

    /// The if_fcslen option is an 8-bit unsigned integer value that specifies
    /// the length of the Frame Check Sequence (in bits) for this interface.
    IfFcsLen(u8),

    /// The if_tsoffset option is a 64-bit integer value that specifies an offset (in seconds)
    /// that must be added to the timestamp of each packet to obtain the absolute timestamp of a packet.
    IfTsOffset(u64),

    /// The if_hardware option is a UTF-8 string containing the description of the interface hardware.
    IfHardware(&'a str)
}


impl<'a> InterfaceDescriptionOption<'a> {

    fn from_slice<B:ByteOrder>(slice: &'a[u8]) -> Result<(&'a[u8], Vec<Self>), PcapError> {

        opts_from_slice::<B, _, _>(slice, |mut slice, type_, _len| {

            let opt = match type_ {

                1 => InterfaceDescriptionOption::Comment(std::str::from_utf8(slice)?),
                2 => InterfaceDescriptionOption::IfName(std::str::from_utf8(slice)?),
                3 => InterfaceDescriptionOption::IfDescription(std::str::from_utf8(slice)?),
                4 => InterfaceDescriptionOption::IfIpv4Addr(slice),
                5 => InterfaceDescriptionOption::IfIpv6Addr(slice),
                6 => InterfaceDescriptionOption::IfMacAddr(slice),
                7 => InterfaceDescriptionOption::IfEulAddr(slice.read_u64::<B>()?),
                8 => InterfaceDescriptionOption::IfSpeed(slice.read_u64::<B>()?),
                9 => InterfaceDescriptionOption::IfTsResol(slice.read_u8()?),
                10 => InterfaceDescriptionOption::IfTzone(slice.read_u32::<B>()?),
                11 => InterfaceDescriptionOption::IfFilter(slice),
                12 => InterfaceDescriptionOption::IfOs(std::str::from_utf8(slice)?),
                13 => InterfaceDescriptionOption::IfFcsLen(slice.read_u8()?),
                14 => InterfaceDescriptionOption::IfTsOffset(slice.read_u64::<B>()?),
                15 => InterfaceDescriptionOption::IfHardware(std::str::from_utf8(slice)?),

                _ => return Err(PcapError::InvalidField("InterfaceDescriptionOption: type invalid"))
            };

            Ok(opt)
        })
    }
}
