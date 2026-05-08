#![allow(clippy::cast_lossless)]

//! Interface Description Block (IDB).

use std::borrow::Cow;
use std::fmt::Display;
use std::io::Write;
use std::num::TryFromIntError;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;
use once_cell::sync::Lazy;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOpt};
use crate::DataLink;
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockContentParseError, ContentValidationError, OptionEntryError, PcapNgWriteError};

/* ----- InterfaceDescriptionBlock ----- */

/// An Interface Description Block (IDB) is the container for information describing an interface
/// on which packet data is captured.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct InterfaceDescriptionBlock<'a> {
    /// A value that defines the link layer type of this interface.
    ///
    /// The list of Standardized Link Layer Type codes is available in the
    /// [tcpdump.org link-layer header types registry.](http://www.tcpdump.org/linktypes.html).
    pub linktype: DataLink,

    /// Maximum number of octets captured from each packet.
    ///
    /// The portion of each packet that exceeds this value will not be stored in the file.
    /// A value of zero indicates no limit.
    pub snaplen: u32,

    /// Options
    pub options: Vec<InterfaceDescriptionOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for InterfaceDescriptionBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockContentParseError> {
        if slice.len() < 8 {
            return Err(BlockContentParseError::BlockContentTooSmall { needed: 8, actual: slice.len() });
        }

        let linktype = (slice.read_u16::<B>().unwrap() as u32).into();

        let reserved = slice.read_u16::<B>().unwrap();
        if reserved != 0 {
            return Err(ContentValidationError::InvalidReservedField(reserved).into());
        }

        let snaplen = slice.read_u32::<B>().unwrap();
        let (slice, options) = InterfaceDescriptionOption::opts_from_slice::<B>(state, None, slice)?;

        let block = InterfaceDescriptionBlock { linktype, snaplen, options };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        writer.write_u16::<B>(u32::from(self.linktype) as u16)?;
        writer.write_u16::<B>(0)?;
        writer.write_u32::<B>(self.snaplen)?;

        let opt_len = InterfaceDescriptionOption::write_opts_to::<B, W>(&self.options, state, None, writer)?;
        Ok(8 + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::InterfaceDescription(self)
    }
}

impl<'a> InterfaceDescriptionBlock<'a> {
    /// Creates a new [`InterfaceDescriptionBlock`]
    pub fn new(linktype: DataLink, snaplen: u32) -> Self {
        Self { linktype, snaplen, options: vec![] }
    }

    /// Returns the timestamp resolution of the interface.
    /// If no ts_resolution is set, defaults to μs.
    pub fn ts_resolution(&self) -> Result<TsResolution, ContentValidationError> {
        let mut ts_resol = Ok(TsResolution::default());

        for opt in &self.options {
            if let InterfaceDescriptionOption::IfTsResol(resol) = opt {
                ts_resol = TsResolution::from_u8(*resol);
                break;
            }
        }

        ts_resol
    }

    /// Returns the timestamp offset of the interface, or zero if it has none.
    pub fn ts_offset(&self) -> i64 {
        for opt in &self.options {
            if let InterfaceDescriptionOption::IfTsOffset(offset) = opt {
                return *offset;
            }
        }

        0
    }
}

/* ----- InterfaceDescriptionOption ----- */

/// The Interface Description Block (IDB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum InterfaceDescriptionOption<'a> {
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
    IfTsOffset(i64),

    /// The if_hardware option is a UTF-8 string containing the description of the interface hardware.
    IfHardware(Cow<'a, str>),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl InterfaceDescriptionOption<'_> {
    const IF_NAME: u16 = 2;
    const IF_DESCRIPTION: u16 = 3;
    const IF_IPV4_ADDR: u16 = 4;
    const IF_IPV6_ADDR: u16 = 5;
    const IF_MAC_ADDR: u16 = 6;
    const IF_EU_ADDR: u16 = 7;
    const IF_SPEED: u16 = 8;
    const IF_TS_RESOL: u16 = 9;
    const IF_T_ZONE: u16 = 10;
    const IF_FILTER: u16 = 11;
    const IF_OS: u16 = 12;
    const IF_FCS_LEN: u16 = 13;
    const IF_TS_OFFSET: u16 = 14;
    const IF_HARDWARE: u16 = 15;
}

impl<'a> PcapNgOption<'a> for InterfaceDescriptionOption<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        mut slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::IF_NAME => InterfaceDescriptionOption::IfName(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::IF_DESCRIPTION => InterfaceDescriptionOption::IfDescription(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::IF_IPV4_ADDR => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfIpv4Addr(Cow::Borrowed(slice))
            },
            Self::IF_IPV6_ADDR => {
                if slice.len() != 17 {
                    return Err(OptionEntryError::WrongSize { expected: 17, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfIpv6Addr(Cow::Borrowed(slice))
            },
            Self::IF_MAC_ADDR => {
                if slice.len() != 6 {
                    return Err(OptionEntryError::WrongSize { expected: 6, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfMacAddr(Cow::Borrowed(slice))
            },
            Self::IF_EU_ADDR => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfEuIAddr(slice.read_u64::<B>().unwrap())
            },
            Self::IF_SPEED => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfSpeed(slice.read_u64::<B>().unwrap())
            },
            Self::IF_TS_RESOL => {
                if slice.len() != 1 {
                    return Err(OptionEntryError::WrongSize { expected: 1, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfTsResol(slice.read_u8().unwrap())
            },
            Self::IF_T_ZONE => {
                if slice.len() != 4 {
                    return Err(OptionEntryError::WrongSize { expected: 4, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfTzone(slice.read_u32::<B>().unwrap())
            },
            Self::IF_FILTER => {
                if slice.is_empty() {
                    return Err(OptionEntryError::WrongSize { expected: 0, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfFilter(Cow::Borrowed(slice))
            },
            Self::IF_OS => InterfaceDescriptionOption::IfOs(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::IF_FCS_LEN => {
                if slice.len() != 1 {
                    return Err(OptionEntryError::WrongSize { expected: 1, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfFcsLen(slice.read_u8().unwrap())
            },
            Self::IF_TS_OFFSET => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceDescriptionOption::IfTsOffset(slice.read_i64::<B>().unwrap())
            },
            Self::IF_HARDWARE => InterfaceDescriptionOption::IfHardware(Cow::Borrowed(std::str::from_utf8(slice)?)),

            _ => InterfaceDescriptionOption::Common(CommonOption::new::<B>(code, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError> {
        match self {
            InterfaceDescriptionOption::IfName(a) => a.write_opt::<B, W>(Self::IF_NAME, writer),
            InterfaceDescriptionOption::IfDescription(a) => a.write_opt::<B, W>(Self::IF_DESCRIPTION, writer),
            InterfaceDescriptionOption::IfIpv4Addr(a) => a.write_opt::<B, W>(Self::IF_IPV4_ADDR, writer),
            InterfaceDescriptionOption::IfIpv6Addr(a) => a.write_opt::<B, W>(Self::IF_IPV6_ADDR, writer),
            InterfaceDescriptionOption::IfMacAddr(a) => a.write_opt::<B, W>(Self::IF_MAC_ADDR, writer),
            InterfaceDescriptionOption::IfEuIAddr(a) => a.write_opt::<B, W>(Self::IF_EU_ADDR, writer),
            InterfaceDescriptionOption::IfSpeed(a) => a.write_opt::<B, W>(Self::IF_SPEED, writer),
            InterfaceDescriptionOption::IfTsResol(a) => a.write_opt::<B, W>(Self::IF_TS_RESOL, writer),
            InterfaceDescriptionOption::IfTzone(a) => a.write_opt::<B, W>(Self::IF_T_ZONE, writer),
            InterfaceDescriptionOption::IfFilter(a) => a.write_opt::<B, W>(Self::IF_FILTER, writer),
            InterfaceDescriptionOption::IfOs(a) => a.write_opt::<B, W>(Self::IF_OS, writer),
            InterfaceDescriptionOption::IfFcsLen(a) => a.write_opt::<B, W>(Self::IF_FCS_LEN, writer),
            InterfaceDescriptionOption::IfTsOffset(a) => a.write_opt::<B, W>(Self::IF_TS_OFFSET, writer),
            InterfaceDescriptionOption::IfHardware(a) => a.write_opt::<B, W>(Self::IF_HARDWARE, writer),
            InterfaceDescriptionOption::Common(a) => a.write_opt::<B, W>(a.code(), writer),
        }
    }

    fn code_name(code: u16) -> &'static str {
        match code {
            Self::IF_NAME => "IfName",
            Self::IF_DESCRIPTION => "IfDescription",
            Self::IF_IPV4_ADDR => "IfIpv4Addr",
            Self::IF_IPV6_ADDR => "IfIpv6Addr",
            Self::IF_MAC_ADDR => "IfMacAddr",
            Self::IF_EU_ADDR => "IfEuIAddr",
            Self::IF_SPEED => "IfSpeed",
            Self::IF_TS_RESOL => "IfTsResol",
            Self::IF_T_ZONE => "IfTzone",
            Self::IF_FILTER => "IfFilter",
            Self::IF_OS => "IfOs",
            Self::IF_FCS_LEN => "IfFcsLen",
            Self::IF_TS_OFFSET => "IfTsOffset",
            Self::IF_HARDWARE => "IfHardware",
            _ => CommonOption::code_name(code),
        }
    }
}

/* ----- TsResolution ----- */

static TS_RESOL_DEC_TO_DURATION: Lazy<Vec<i128>> = Lazy::new(|| (0..10).map(|i| 10_i128.pow(9 - i)).collect());

/// Timestamp resolution of an interface.
///
/// Can be either binary (2^-resol)s or decimal (10^-resol)s.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TsResolution {
    /// Whether the resolution is binary or decimal.
    is_bin: bool,
    /// The resolution itself.
    resol: u8,
}

impl TsResolution {
    /// Second resolution
    pub const SEC: Self = TsResolution { is_bin: false, resol: 0 };
    /// Milli-second resolution
    pub const MILLI: Self = TsResolution { is_bin: false, resol: 3 };
    /// Micro-second resolution
    pub const MICRO: Self = TsResolution { is_bin: false, resol: 6 };
    /// Nano-second resolution
    pub const NANO: Self = TsResolution { is_bin: false, resol: 9 };

    /// Creates a new [`TsResolution`].
    ///
    /// - If binary, the resolution must be in the range [0-29].
    /// - If decimal, the resolution must be in the range [0-9].
    pub fn new(is_bin: bool, resol: u8) -> Result<Self, ContentValidationError> {
        // 2^29 is the last power of 2 inferior to 1_000_000_000 which is the number of nanosec in one second
        if is_bin && resol > 29 {
            let resol_enc = TsResolution { is_bin, resol }.to_u8();
            return Err(ContentValidationError::InvalidTsResolution(resol_enc, is_bin, resol));
        }

        if !is_bin && resol > 9 {
            let resol_enc = TsResolution { is_bin, resol }.to_u8();
            return Err(ContentValidationError::InvalidTsResolution(resol_enc, is_bin, resol));
        }

        Ok(TsResolution { is_bin, resol })
    }

    /// Creates a new [`TsResolution`] from an [`u8`].
    ///
    /// - If binary, the resolution must be in the range [0-29].
    /// - If decimal, the resolution must be in the range [0-9].
    pub fn from_u8(ts_resol: u8) -> Result<Self, ContentValidationError> {
        let is_bin = (ts_resol >> 7) & 0x1 == 1;
        let resol = ts_resol & 0x7F;

        Self::new(is_bin, resol)
    }

    /// Encodes the [`TsResolution`] into an [`u8`] for storage in the file.
    pub fn to_u8(self) -> u8 {
        (self.is_bin as u8) << 7 | self.resol
    }

    /// Decode an encoded timestamp using the current resolution.
    pub fn decode_timestamp(&self, ts_raw: u64) -> i128 {
        if self.is_bin {
            // We don't use a pre-computed TS_RESOL_BIN here because we would lose too much precision for higher resolutions.
            // Example: 2^29 resol => 10^9 / 2^29 => 1.86ns resolution rounded to 1ns
            (ts_raw as i128 * 1_000_000_000_i128) / (1_i128 << self.resol)
        } else {
            ts_raw as i128 * TS_RESOL_DEC_TO_DURATION[self.resol as usize]
        }
    }

    /// Encode a timestamp with the current resolution.
    ///
    /// # Errors
    /// - Timestamp can't be encoded with the current resolution on a u64
    pub fn encode_timestamp(&self, timestamp_ns: i128) -> Result<u64, TryFromIntError> {
        let ts = if self.is_bin {
            (timestamp_ns * (1_i128 << self.resol)) / 1_000_000_000_i128
        } else {
            timestamp_ns / TS_RESOL_DEC_TO_DURATION[self.resol as usize]
        };

        ts.try_into()
    }

    /// Returns whether the resolution is binary or decimal.
    pub fn is_bin(&self) -> bool {
        self.is_bin
    }

    /// Returns the resolution value.
    pub fn resolution(&self) -> u8 {
        self.resol
    }
}

impl Default for TsResolution {
    /// Default to micro-seconds resolution
    fn default() -> Self {
        Self::MICRO
    }
}

impl Display for TsResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_bin {
            write!(f, "2^-{}s", self.resol)
        } else {
            write!(f, "10^-{}s", self.resol)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TsResolution;

    /// Test that multiple encode / decode doesn't drift more than by one step.
    #[test]
    fn binary_timestamp_roundtrip_loses_at_most_one_tick_min() {
        let resolution = TsResolution::new(true, 10).unwrap();

        let mut raw = 1;
        for _ in 0..100 {
            let ts = resolution.decode_timestamp(raw);
            raw = resolution.encode_timestamp(ts).unwrap();
        }

        assert_eq!(raw, 0);
    }

    /// Test that multiple encode / decode doesn't drift more than by one step.
    #[test]
    fn binary_timestamp_roundtrip_loses_at_most_one_tick_max() {
        let resolution = TsResolution::new(true, 10).unwrap();

        let mut raw = u64::MAX;
        for _ in 0..100 {
            let ts = resolution.decode_timestamp(raw);
            raw = resolution.encode_timestamp(ts).unwrap();
        }

        assert_eq!(raw, 18446744073709551614);
    }
}
