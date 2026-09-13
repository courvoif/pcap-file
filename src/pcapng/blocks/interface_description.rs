#![allow(clippy::cast_lossless)]

//! Interface Description Block (IDB).

use std::borrow::Cow;
use std::fmt::Display;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;
use once_cell::sync::Lazy;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOpt, write_opt_with_header_and_pad};
use crate::DataLink;
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockContentParseError, ContentValidationError, OptionEntryError, PcapNgWriteError};

/* ----- InterfaceDescriptionBlock ----- */

/// Interface Description Block (IDB).
///
/// Describes an interface on which packet data was captured.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct InterfaceDescriptionBlock<'a> {
    /// Link-layer type of this interface.
    ///
    /// The list of Standardized Link Layer Type codes is available in the
    /// [tcpdump.org link-layer header types registry.](http://www.tcpdump.org/linktypes.html).
    pub linktype: DataLink,

    /// Maximum number of bytes captured from each packet.
    ///
    /// Packet data beyond this limit is not stored in the file.
    /// A value of zero indicates no limit.
    pub snaplen: u32,

    /// Block options.
    pub options: Vec<InterfaceDescriptionOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for InterfaceDescriptionBlock<'a> {
    fn from_slice<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockContentParseError> {
        if slice.len() < 8 {
            return Err(BlockContentParseError::BlockContentTooSmall {
                needed: 8,
                actual: slice.len(),
            });
        }

        let linktype = (slice.read_u16::<B>().unwrap() as u32).into();

        let reserved = slice.read_u16::<B>().unwrap();
        if reserved != 0 {
            return Err(ContentValidationError::InvalidReservedField(reserved).into());
        }

        let snaplen = slice.read_u32::<B>().unwrap();
        let (slice, options) = InterfaceDescriptionOption::opts_from_slice::<B>(state, None, slice)?;

        let block = InterfaceDescriptionBlock {
            linktype,
            snaplen,
            options,
        };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        let datalink: u16 = u32::from(self.linktype).try_into().map_err(|_| {
            PcapNgWriteError::validation_error(
                "InterfaceDescriptionBlock.linktype",
                ContentValidationError::InvalidLinkLayerType(self.linktype),
            )
        })?;

        writer.write_u16::<B>(datalink)?;
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
    /// Creates a new [`InterfaceDescriptionBlock`].
    pub fn new(linktype: DataLink, snaplen: u32) -> Self {
        Self {
            linktype,
            snaplen,
            options: vec![],
        }
    }

    /// Returns the timestamp resolution of the interface.
    /// Defaults to microseconds when no timestamp-resolution option is present.
    pub fn ts_resolution(&self) -> InterfaceTsResolution {
        let mut ts_resol = InterfaceTsResolution::default();

        for opt in &self.options {
            if let InterfaceDescriptionOption::IfTsResol(resol) = opt {
                ts_resol = *resol;
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

/// Interface Description Block (IDB) options.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum InterfaceDescriptionOption<'a> {
    /// Name of the device used to capture data.
    IfName(Cow<'a, str>),

    /// Description of the device used to capture data.
    IfDescription(Cow<'a, str>),

    /// IPv4 network address and corresponding netmask for the interface.
    IfIpv4Addr(IfIpv4AddrOpt),

    /// IPv6 network address and corresponding prefix length for the interface.
    IfIpv6Addr(IfIpv6AddrOpt),

    /// Interface hardware MAC address, if available.
    IfMacAddr([u8; 6]),

    /// Interface hardware EUI address, if available.
    IfEuiAddr(u64),

    /// Interface speed in bits per second.
    IfSpeed(u64),

    /// Timestamp resolution used by the interface.
    IfTsResol(InterfaceTsResolution),

    /// Time zone for GMT support.
    IfTzone(u32),

    /// Filter used to capture traffic.
    IfFilter(Cow<'a, [u8]>),

    /// Operating system on which this interface is installed.
    IfOs(Cow<'a, str>),

    /// Length of the Frame Check Sequence, in bits, for this interface.
    IfFcsLen(u8),

    /// Offset, in seconds, added to packet timestamps from this interface.
    IfTsOffset(i64),

    /// Description of the interface hardware.
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
    const IF_EUI_ADDR: u16 = 7;
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
            Self::IF_DESCRIPTION => {
                InterfaceDescriptionOption::IfDescription(Cow::Borrowed(std::str::from_utf8(slice)?))
            }
            Self::IF_IPV4_ADDR => InterfaceDescriptionOption::IfIpv4Addr(IfIpv4AddrOpt::from_slice(slice)?),
            Self::IF_IPV6_ADDR => InterfaceDescriptionOption::IfIpv6Addr(IfIpv6AddrOpt::from_slice(slice)?),
            Self::IF_MAC_ADDR => {
                if slice.len() != 6 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 6,
                        actual: slice.len(),
                    });
                }
                InterfaceDescriptionOption::IfMacAddr(slice.try_into().expect("slice length checked above"))
            }
            Self::IF_EUI_ADDR => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 8,
                        actual: slice.len(),
                    });
                }
                InterfaceDescriptionOption::IfEuiAddr(slice.read_u64::<B>().unwrap())
            }
            Self::IF_SPEED => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 8,
                        actual: slice.len(),
                    });
                }
                InterfaceDescriptionOption::IfSpeed(slice.read_u64::<B>().unwrap())
            }
            Self::IF_TS_RESOL => {
                if slice.len() != 1 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 1,
                        actual: slice.len(),
                    });
                }

                let raw_resol = slice.read_u8().unwrap();
                let resol = InterfaceTsResolution::from_u8(raw_resol)?;
                InterfaceDescriptionOption::IfTsResol(resol)
            }
            Self::IF_T_ZONE => {
                if slice.len() != 4 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 4,
                        actual: slice.len(),
                    });
                }
                InterfaceDescriptionOption::IfTzone(slice.read_u32::<B>().unwrap())
            }
            Self::IF_FILTER => {
                if slice.is_empty() {
                    return Err(OptionEntryError::WrongSize {
                        expected: 0,
                        actual: slice.len(),
                    });
                }
                InterfaceDescriptionOption::IfFilter(Cow::Borrowed(slice))
            }
            Self::IF_OS => InterfaceDescriptionOption::IfOs(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::IF_FCS_LEN => {
                if slice.len() != 1 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 1,
                        actual: slice.len(),
                    });
                }
                InterfaceDescriptionOption::IfFcsLen(slice.read_u8().unwrap())
            }
            Self::IF_TS_OFFSET => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize {
                        expected: 8,
                        actual: slice.len(),
                    });
                }
                InterfaceDescriptionOption::IfTsOffset(slice.read_i64::<B>().unwrap())
            }
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
            InterfaceDescriptionOption::IfEuiAddr(a) => a.write_opt::<B, W>(Self::IF_EUI_ADDR, writer),
            InterfaceDescriptionOption::IfSpeed(a) => a.write_opt::<B, W>(Self::IF_SPEED, writer),
            InterfaceDescriptionOption::IfTsResol(a) => a.to_u8().write_opt::<B, W>(Self::IF_TS_RESOL, writer),
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
            Self::IF_EUI_ADDR => "IfEuiAddr",
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

/* ----- IfIpv4AddrOpt ----- */

/// IPv4 address option value for an Interface Description Block.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IfIpv4AddrOpt {
    /// IPv4 address assigned to the interface.
    pub ip: Ipv4Addr,
    /// Network mask associated with the IPv4 address.
    pub netmask: [u8; 4],
}

impl IfIpv4AddrOpt {
    /// Parses an IPv4 address and network mask from an option value.
    ///
    /// # Errors
    ///
    /// - Returns [`OptionEntryError::WrongSize`] unless `slice` contains exactly
    ///   eight bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, OptionEntryError> {
        if slice.len() != 8 {
            return Err(OptionEntryError::WrongSize {
                expected: 8,
                actual: slice.len(),
            });
        }

        let ip: [u8; 4] = (&slice[..4]).try_into().expect("slice has eight bytes");
        let netmask: [u8; 4] = (&slice[4..]).try_into().expect("slice has eight bytes");

        Ok(Self {
            ip: Ipv4Addr::from_octets(ip),
            netmask,
        })
    }
}

impl WriteOpt for IfIpv4AddrOpt {
    fn write_opt<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_and_pad::<B, _>(writer, code, 8, |writer| {
            writer.write_all(&self.ip.octets())?;
            writer.write_all(&self.netmask)
        })
    }
}

/* ----- IfIpv6AddrOpt ----- */

/// IPv6 address option value for an Interface Description Block.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IfIpv6AddrOpt {
    /// IPv6 address assigned to the interface.
    pub ip: Ipv6Addr,
    /// Prefix length associated with the IPv6 address.
    pub prefix_len: u8,
}

impl IfIpv6AddrOpt {
    /// Parses an IPv6 address and prefix length from an option value.
    ///
    /// # Errors
    ///
    /// - Returns [`OptionEntryError::WrongSize`] unless `slice` contains exactly
    ///   17 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, OptionEntryError> {
        if slice.len() != 17 {
            return Err(OptionEntryError::WrongSize {
                expected: 17,
                actual: slice.len(),
            });
        }

        let ip: [u8; 16] = (&slice[..16]).try_into().expect("slice has 17 bytes");

        Ok(Self {
            ip: Ipv6Addr::from_octets(ip),
            prefix_len: slice[16],
        })
    }
}

impl WriteOpt for IfIpv6AddrOpt {
    fn write_opt<B: ByteOrder, W: Write>(&self, code: u16, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        write_opt_with_header_and_pad::<B, _>(writer, code, 17, |writer| {
            writer.write_all(&self.ip.octets())?;
            writer.write_u8(self.prefix_len)
        })
    }
}

/* ----- TsResolution ----- */

static TS_RESOL_DEC_TO_DURATION: Lazy<Vec<u128>> = Lazy::new(|| (0..10).map(|i| 10_u128.pow(9 - i)).collect());

/// Timestamp resolution of an interface.
///
/// Uses either a binary (`2^-resolution`) or decimal (`10^-resolution`) scale.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InterfaceTsResolution {
    /// Whether the resolution is binary or decimal.
    is_bin: bool,
    /// The resolution itself.
    resol: u8,
}

impl InterfaceTsResolution {
    /// Second resolution
    pub const SEC: Self = InterfaceTsResolution {
        is_bin: false,
        resol: 0,
    };
    /// Millisecond resolution
    pub const MILLI: Self = InterfaceTsResolution {
        is_bin: false,
        resol: 3,
    };
    /// Microsecond resolution
    pub const MICRO: Self = InterfaceTsResolution {
        is_bin: false,
        resol: 6,
    };
    /// Nanosecond resolution
    pub const NANO: Self = InterfaceTsResolution {
        is_bin: false,
        resol: 9,
    };

    /// Creates a new [`InterfaceTsResolution`].
    ///
    /// # Errors
    ///
    /// - Returns an error if a binary resolution is greater than 29 or a
    ///   decimal resolution is greater than 9.
    pub fn new(is_bin: bool, resol: u8) -> Result<Self, ContentValidationError> {
        // 2^29 is the last power of 2 inferior to 1_000_000_000 which is the number of nanosec in one second
        if is_bin && resol > 29 {
            let resol_enc = InterfaceTsResolution { is_bin, resol }.to_u8();
            return Err(ContentValidationError::InvalidTsResolution(resol_enc, is_bin, resol));
        }

        if !is_bin && resol > 9 {
            let resol_enc = InterfaceTsResolution { is_bin, resol }.to_u8();
            return Err(ContentValidationError::InvalidTsResolution(resol_enc, is_bin, resol));
        }

        Ok(InterfaceTsResolution { is_bin, resol })
    }

    /// Decodes an [`InterfaceTsResolution`] from a [`u8`].
    ///
    /// # Errors
    ///
    /// - Returns an error if the encoded binary resolution is greater than 29
    ///   or the encoded decimal resolution is greater than 9.
    pub fn from_u8(ts_resol: u8) -> Result<Self, ContentValidationError> {
        let is_bin = (ts_resol >> 7) & 0x1 == 1;
        let resol = ts_resol & 0x7F;

        Self::new(is_bin, resol)
    }

    /// Encodes the [`InterfaceTsResolution`] into a [`u8`] for storage in the file.
    pub fn to_u8(self) -> u8 {
        (self.is_bin as u8) << 7 | self.resol
    }

    /// Decode an encoded timestamp using the current resolution.
    pub fn decode_timestamp(&self, ts_raw: u64) -> Duration {
        let timestamp_ns = if self.is_bin {
            // We don't use a pre-computed TS_RESOL_BIN here because we would lose too much precision for higher resolutions.
            // Example: 2^29 resol => 10^9 / 2^29 => 1.86ns resolution rounded to 1ns
            (ts_raw as u128 * 1_000_000_000_u128) >> self.resol
        } else {
            ts_raw as u128 * TS_RESOL_DEC_TO_DURATION[self.resol as usize]
        };

        Duration::from_nanos_u128(timestamp_ns)
    }

    /// Encode a timestamp with the current resolution.
    ///
    /// # Errors
    ///
    /// - Returns an error if the timestamp cannot be represented as a `u64`
    ///   using the current resolution.
    pub fn encode_timestamp(&self, timestamp: Duration) -> Result<u64, ContentValidationError> {
        let timestamp_ns = timestamp.as_nanos();
        let ts = if self.is_bin {
            timestamp_ns
                .checked_shl(self.resol.into())
                .ok_or(ContentValidationError::FailedToEncodeTimestamp {
                    timestamp,
                    resolution: *self,
                    offset: 0,
                })?
                / 1_000_000_000_u128
        } else {
            timestamp_ns / TS_RESOL_DEC_TO_DURATION[self.resol as usize]
        };

        ts.try_into()
            .map_err(|_| ContentValidationError::FailedToEncodeTimestamp {
                timestamp,
                resolution: *self,
                offset: 0,
            })
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

impl Default for InterfaceTsResolution {
    /// Defaults to microsecond resolution
    fn default() -> Self {
        Self::MICRO
    }
}

impl Display for InterfaceTsResolution {
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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use byteorder_slice::{BigEndian, LittleEndian};

    use super::{ContentValidationError, IfIpv4AddrOpt, IfIpv6AddrOpt, InterfaceTsResolution, WriteOpt};
    use crate::pcapng::errors::OptionEntryError;

    #[test]
    fn ipv4_address_option_roundtrip() {
        let value = [192, 0, 2, 1, 255, 255, 255, 0];
        let option = IfIpv4AddrOpt::from_slice(&value).unwrap();

        assert_eq!(option.ip, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(option.netmask, [255, 255, 255, 0]);

        let mut encoded = Vec::new();
        assert_eq!(option.write_opt::<BigEndian, _>(4, &mut encoded).unwrap(), 12);
        assert_eq!(encoded, [0, 4, 0, 8, 192, 0, 2, 1, 255, 255, 255, 0]);
    }

    #[test]
    fn ipv6_address_option_roundtrip() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut value = ip.octets().to_vec();
        value.push(64);

        let option = IfIpv6AddrOpt::from_slice(&value).unwrap();
        assert_eq!(option.ip, ip);
        assert_eq!(option.prefix_len, 64);

        let mut encoded = Vec::new();
        assert_eq!(option.write_opt::<LittleEndian, _>(5, &mut encoded).unwrap(), 24);
        assert_eq!(&encoded[..4], &[5, 0, 17, 0]);
        assert_eq!(&encoded[4..21], value);
        assert_eq!(&encoded[21..], &[0, 0, 0]);
    }

    #[test]
    fn address_options_reject_invalid_sizes() {
        assert!(matches!(
            IfIpv4AddrOpt::from_slice(&[0; 7]),
            Err(OptionEntryError::WrongSize { expected: 8, actual: 7 })
        ));
        assert!(matches!(
            IfIpv6AddrOpt::from_slice(&[0; 16]),
            Err(OptionEntryError::WrongSize {
                expected: 17,
                actual: 16
            })
        ));
    }

    /// Test that multiple encode / decode doesn't drift more than by one step.
    #[test]
    fn binary_timestamp_roundtrip_loses_at_most_one_tick_min() {
        let resolution = InterfaceTsResolution::new(true, 10).unwrap();

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
        let resolution = InterfaceTsResolution::new(true, 10).unwrap();

        let mut raw = u64::MAX;
        for _ in 0..100 {
            let ts = resolution.decode_timestamp(raw);
            raw = resolution.encode_timestamp(ts).unwrap();
        }

        assert_eq!(raw, 18446744073709551614);
    }

    #[test]
    fn binary_timestamp_encode_overflow_returns_invalid_timestamp() {
        let resolution = InterfaceTsResolution::new(true, 29).unwrap();

        let error = resolution.encode_timestamp(Duration::MAX).unwrap_err();

        assert!(matches!(
            error,
            ContentValidationError::FailedToEncodeTimestamp {
                timestamp,
                resolution: error_resolution,
                offset,
            } if timestamp == Duration::MAX
                    && error_resolution == resolution
                    && offset == 0
        ));
    }
}
