#![allow(clippy::cast_lossless)]

use std::borrow::Cow;
use std::io::Result as IoResult;
use std::io::Write;

use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};
use derive_into_owned::IntoOwned;

use crate::DataLink;
use crate::errors::PcapError;
use crate::pcapng::{CustomBinaryOption, CustomUtf8Option, PcapNgBlock, PcapNgOption, UnknownOption, WriteOptTo, BlockType, ParsedBlock};

/// An Interface Description Block (IDB) is the container for information describing an interface
/// on which packet data is captured.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
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

impl<'a> PcapNgBlock<'a> for InterfaceDescriptionBlock<'a> {

    const BLOCK_TYPE: BlockType = BlockType::InterfaceDescription;

    fn from_slice<B:ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {

        if slice.len() < 8 {
            return Err(PcapError::InvalidField("InterfaceDescriptionBlock: block length < 8"));
        }

        let linktype = (slice.read_u16::<B>()? as u32).into();
        let reserved = slice.read_u16::<B>()?;
        let snaplen = slice.read_u32::<B>()?;
        let (slice, options) = InterfaceDescriptionOption::opts_from_slice::<B>(slice)?;

        let block = InterfaceDescriptionBlock {
            linktype,
            reserved,
            snaplen,
            options
        };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        writer.write_u16::<B>(u32::from(self.linktype) as u16)?;
        writer.write_u16::<B>(self.reserved)?;
        writer.write_u32::<B>(self.snaplen)?;

        let opt_len = InterfaceDescriptionOption::write_opts_to::<B, W>(&self.options, writer)?;
        Ok(8 + opt_len)
    }

    fn into_parsed(self) -> ParsedBlock<'a> {
        ParsedBlock::InterfaceDescription(self)
    }
}

impl InterfaceDescriptionBlock<'static> {

    pub fn new(linktype: DataLink, snaplen: u32) -> Self {

        Self {
            linktype,
            reserved: 0,
            snaplen,
            options: vec![]
        }
    }
}

#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum InterfaceDescriptionOption<'a> {

    Comment(Cow<'a, str>),

    /// The if_name option is a UTF-8 string containing the name of the device used to capture data.
    IfName(Cow<'a, str>),

    /// The if_description option is a UTF-8 string containing the description of the device used to capture data.
    IfDescription(Cow<'a, str>),

    /// The if_IPv4addr option is an IPv4 network address and corresponding netmask for the interface.
    IfIpv4Addr(Cow<'a, [u8]>),

    /// The if_IPv6addr option is an IPv6 network address and corresponding prefix length for the interface.
    IfIpv6Addr(Cow<'a, [u8]>),

    /// The if_MACaddr option is the Interface Hardware MAC address (48 bits), if available.
    IfMacAddr(Cow<'a, [u8]>),

    /// The if_EUIaddr option is the Interface Hardware EUI address (64 bits), if available.
    IfEuIAddr(u64),

    /// The if_speed option is a 64-bit number for the Interface speed (in bits per second).
    IfSpeed(u64),

    /// The if_tsresol option identifies the resolution of timestamps.
    IfTsResol(u8),

    /// The if_tzone option identifies the time zone for GMT support.
    IfTzone(u32),

    /// The if_filter option identifies the filter (e.g. "capture only TCP traffic") used to capture traffic.
    IfFilter(Cow<'a, [u8]>),

    /// The if_os option is a UTF-8 string containing the name of the operating system
    /// of the machine in which this interface is installed.
    IfOs(Cow<'a, str>),

    /// The if_fcslen option is an 8-bit unsigned integer value that specifies
    /// the length of the Frame Check Sequence (in bits) for this interface.
    IfFcsLen(u8),

    /// The if_tsoffset option is a 64-bit integer value that specifies an offset (in seconds)
    /// that must be added to the timestamp of each packet to obtain the absolute timestamp of a packet.
    IfTsOffset(u64),

    /// The if_hardware option is a UTF-8 string containing the description of the interface hardware.
    IfHardware(Cow<'a, str>),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>)
}

impl<'a> PcapNgOption<'a> for InterfaceDescriptionOption<'a> {

    fn from_slice<B: ByteOrder>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {

        let opt = match code {

            1 => InterfaceDescriptionOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => InterfaceDescriptionOption::IfName(Cow::Borrowed(std::str::from_utf8(slice)?)),
            3 => InterfaceDescriptionOption::IfDescription(Cow::Borrowed(std::str::from_utf8(slice)?)),
            4 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfIpv4Addr length != 8"))
                }
                InterfaceDescriptionOption::IfIpv4Addr(Cow::Borrowed(slice))
            },
            5 => {
                if slice.len() != 17 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfIpv6Addr length != 17"))
                }
                InterfaceDescriptionOption::IfIpv6Addr(Cow::Borrowed(slice))
            },
            6 => {
                if slice.len() != 6 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfMacAddr length != 6"))
                }
                InterfaceDescriptionOption::IfMacAddr(Cow::Borrowed(slice))
            },
            7 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfEuIAddr length != 8"))
                }
                InterfaceDescriptionOption::IfEuIAddr(slice.read_u64::<B>()?)
            },
            8 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfSpeed length != 8"))
                }
                InterfaceDescriptionOption::IfSpeed(slice.read_u64::<B>()?)
            },
            9 => {
                if slice.len() != 1 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfTsResol length != 1"))
                }
                InterfaceDescriptionOption::IfTsResol(slice.read_u8()?)
            },
            10 => {
                if slice.len() != 1 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfTzone length != 1"))
                }
                InterfaceDescriptionOption::IfTzone(slice.read_u32::<B>()?)
            },
            11 => {
                if slice.is_empty() {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfFilter is empty"))
                }
                InterfaceDescriptionOption::IfFilter(Cow::Borrowed(slice))
            },
            12 => InterfaceDescriptionOption::IfOs(Cow::Borrowed(std::str::from_utf8(slice)?)),
            13 => {
                if slice.len() != 1 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfFcsLen length != 1"))
                }
                InterfaceDescriptionOption::IfFcsLen(slice.read_u8()?)
            },
            14 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfTsOffset length != 8"))
                }
                InterfaceDescriptionOption::IfTsOffset(slice.read_u64::<B>()?)
            },
            15 => InterfaceDescriptionOption::IfHardware(Cow::Borrowed(std::str::from_utf8(slice)?)),

            2988 | 19372 => InterfaceDescriptionOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
            2989 | 19373 => InterfaceDescriptionOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

            _ => InterfaceDescriptionOption::Unknown(UnknownOption::new(code, length, slice))
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        match self {
            InterfaceDescriptionOption::Comment(a) => a.write_opt_to::<B, W>(1, writer),
            InterfaceDescriptionOption::IfName(a) => a.write_opt_to::<B, W>(2, writer),
            InterfaceDescriptionOption::IfDescription(a) => a.write_opt_to::<B, W>(3, writer),
            InterfaceDescriptionOption::IfIpv4Addr(a) => a.write_opt_to::<B, W>(4, writer),
            InterfaceDescriptionOption::IfIpv6Addr(a) => a.write_opt_to::<B, W>(5, writer),
            InterfaceDescriptionOption::IfMacAddr(a) => a.write_opt_to::<B, W>(6, writer),
            InterfaceDescriptionOption::IfEuIAddr(a) => a.write_opt_to::<B, W>(7, writer),
            InterfaceDescriptionOption::IfSpeed(a) => a.write_opt_to::<B, W>(8, writer),
            InterfaceDescriptionOption::IfTsResol(a) => a.write_opt_to::<B, W>(9, writer),
            InterfaceDescriptionOption::IfTzone(a) => a.write_opt_to::<B, W>(10, writer),
            InterfaceDescriptionOption::IfFilter(a) => a.write_opt_to::<B, W>(11, writer),
            InterfaceDescriptionOption::IfOs(a) => a.write_opt_to::<B, W>(12, writer),
            InterfaceDescriptionOption::IfFcsLen(a) => a.write_opt_to::<B, W>(13, writer),
            InterfaceDescriptionOption::IfTsOffset(a) => a.write_opt_to::<B, W>(14, writer),
            InterfaceDescriptionOption::IfHardware(a) => a.write_opt_to::<B, W>(15, writer),
            InterfaceDescriptionOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer),
            InterfaceDescriptionOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer),
            InterfaceDescriptionOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer),
        }
    }
}