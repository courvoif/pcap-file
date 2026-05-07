//! Name Resolution Block (NRB).

use std::borrow::Cow;
use std::io::{Result as IoResult, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOptTo};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockContentParseError, ContentValidationError, OptionEntryError, PcapNgWriteError};

/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct NameResolutionBlock<'a> {
    /// Records
    pub records: Vec<Record<'a>>,
    /// Options
    pub options: Vec<NameResolutionOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for NameResolutionBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockContentParseError> {
        let mut records = Vec::new();

        loop {
            let (slice_tmp, record) = Record::from_slice::<B>(slice)?;
            slice = slice_tmp;

            match record {
                Record::End => break,
                _ => records.push(record),
            }
        }

        let (rem, options) = NameResolutionOption::opts_from_slice::<B>(state, None, slice)?;

        let block = NameResolutionBlock { records, options };

        Ok((rem, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        let mut len = 0;

        for record in &self.records {
            len += record.write_to::<B, _>(writer)?;
        }
        len += Record::End.write_to::<B, _>(writer)?;

        len += NameResolutionOption::write_opts_to::<B, _>(&self.options, state, None, writer)?;

        Ok(len)
    }

    fn into_block(self) -> Block<'a> {
        Block::NameResolution(self)
    }
}

/// Resolution block record types
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Record<'a> {
    /// End of the records
    End,
    /// Ipv4 records
    Ipv4(Ipv4Record<'a>),
    /// Ipv6 records
    Ipv6(Ipv6Record<'a>),
    /// Unknown records
    Unknown(UnknownRecord<'a>),
}

impl<'a> Record<'a> {
    /// Parse a [`Record`] from a slice
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockContentParseError> {
        if slice.len() < 4 {
            return Err(BlockContentParseError::BlockContentTooSmall { needed: 4, actual: slice.len() });
        }

        let type_ = slice.read_u16::<B>().unwrap();
        let length = slice.read_u16::<B>().unwrap() as usize;
        let pad_len = (4 - length % 4) % 4;

        if slice.len() < length + pad_len {
            return Err(BlockContentParseError::BlockContentTooSmall { needed: length + pad_len, actual: slice.len() });
        }
        let value = &slice[..length];

        let record = match type_ {
            0 => {
                if length != 0 {
                    return Err(ContentValidationError::RecordWrongSize { expected: 0, actual: length }.into());
                }

                Record::End
            },

            1 => {
                let record = Ipv4Record::from_slice(value)?;
                Record::Ipv4(record)
            },

            2 => {
                let record = Ipv6Record::from_slice(value)?;
                Record::Ipv6(record)
            },

            _ => {
                let record = UnknownRecord::new(type_, value);
                Record::Unknown(record)
            },
        };

        let len = length + pad_len;

        Ok((&slice[len..], record))
    }

    /// Write a [`Record`] to a writer
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        match self {
            Record::End => {
                writer.write_u16::<B>(0)?;
                writer.write_u16::<B>(0)?;

                Ok(4)
            },
            Record::Ipv4(a) => {
                let len = a.write_to::<B, _>(&mut std::io::sink())?;
                let pad_len = (4 - len % 4) % 4;

                let len: u16 = len.try_into().map_err(|_| PcapNgWriteError::Validation {
                    field: "Ipv4Record.length",
                    source: ContentValidationError::RecordTooBig(len),
                })?;

                writer.write_u16::<B>(1)?;
                writer.write_u16::<B>(len)?;
                a.write_to::<B, _>(writer)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len as usize + pad_len)
            },
            Record::Ipv6(a) => {
                let len = a.write_to::<B, _>(&mut std::io::sink())?;
                let pad_len = (4 - len % 4) % 4;

                let len: u16 = len.try_into().map_err(|_| PcapNgWriteError::Validation {
                    field: "Ipv6Record.length",
                    source: ContentValidationError::RecordTooBig(len),
                })?;

                writer.write_u16::<B>(2)?;
                writer.write_u16::<B>(len)?;
                a.write_to::<B, _>(writer)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len as usize + pad_len)
            },
            Record::Unknown(a) => {
                let len = a.value.len();
                let pad_len = (4 - len % 4) % 4;

                let len: u16 = len.try_into().map_err(|_| PcapNgWriteError::Validation {
                    field: "UnknownRecord.length",
                    source: ContentValidationError::RecordTooBig(len),
                })?;

                writer.write_u16::<B>(a.type_)?;
                writer.write_u16::<B>(len)?;
                writer.write_all(&a.value)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len as usize + pad_len)
            },
        }
    }
}

/// Ipv4 records
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv4Record<'a> {
    /// IPv4 Addr
    pub ip_addr: Ipv4Addr,
    /// Fqdn
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv4Record<'a> {
    /// Parse a [`Ipv4Record`] from a slice
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockContentParseError> {
        if slice.len() < 6 {
            return Err(ContentValidationError::RecordWrongMinSize { min: 6, actual: slice.len() }.into());
        }

        let ip_addr_oct: [u8; 4] = slice.read_slice(4).unwrap().try_into().unwrap();
        let ip_addr = Ipv4Addr::from_octets(ip_addr_oct);

        let mut names = vec![];
        for name in slice.split(|&b| b == 0) {
            if name.is_empty() {
                break;
            }
            names.push(Cow::Borrowed(std::str::from_utf8(name).map_err(ContentValidationError::RecordNameNotUtf8)?));
        }

        if names.is_empty() {
            return Err(ContentValidationError::RecordNamesEmpty.into());
        }

        let record = Ipv4Record { ip_addr, names };

        Ok(record)
    }

    /// Write a [`Ipv4Record`] to a writter
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        let mut len = 4;

        writer.write_all(&self.ip_addr.octets())?;

        for name in &self.names {
            writer.write_all(name.as_bytes())?;
            writer.write_u8(0)?;

            len += name.len();
            len += 1;
        }

        Ok(len)
    }
}

/// Ipv6 records
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv6Record<'a> {
    /// Ipv6 addr
    pub ip_addr: Ipv6Addr,
    /// Fqdn
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv6Record<'a> {
    /// Parse a [`Ipv6Record`] from a slice
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockContentParseError> {
        if slice.len() < 18 {
            return Err(ContentValidationError::RecordWrongMinSize { min: 18, actual: slice.len() }.into());
        }

        let ip_addr_oct: [u8; 16] = slice.read_slice(16).unwrap().try_into().unwrap();
        let ip_addr = Ipv6Addr::from_octets(ip_addr_oct);

        let mut names = vec![];
        for name in slice.split(|&b| b == 0) {
            if name.is_empty() {
                break;
            }
            names.push(Cow::Borrowed(std::str::from_utf8(name).map_err(ContentValidationError::RecordNameNotUtf8)?));
        }

        if names.is_empty() {
            return Err(ContentValidationError::RecordNamesEmpty.into());
        }

        let record = Ipv6Record { ip_addr, names };

        Ok(record)
    }

    /// Write a [`Ipv6Record`] to a writter
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        let mut len = 16;

        writer.write_all(&self.ip_addr.octets())?;
        for name in &self.names {
            writer.write_all(name.as_bytes())?;
            writer.write_u8(0)?;

            len += name.len();
            len += 1;
        }

        Ok(len)
    }
}

/// Unknown records
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownRecord<'a> {
    /// Records type
    pub type_: u16,
    /// Record body
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownRecord<'a> {
    /// Creates a new [`UnknownRecord`]
    fn new(type_: u16, value: &'a [u8]) -> Self {
        UnknownRecord { type_, value: Cow::Borrowed(value) }
    }
}

/// The Name Resolution Block (NRB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum NameResolutionOption<'a> {
    /// The ns_dnsname option is a UTF-8 string containing the name of the machine (DNS server) used to perform the name resolution.
    NsDnsName(Cow<'a, str>),

    /// The ns_dnsIP4addr option specifies the IPv4 address of the DNS server.
    NsDnsIpv4Addr(Cow<'a, [u8]>),

    /// The ns_dnsIP6addr option specifies the IPv6 address of the DNS server.
    NsDnsIpv6Addr(Cow<'a, [u8]>),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl NameResolutionOption<'_> {
    const NS_DNS_NAME: u16 = 2;
    const NS_DNS_IPV4_ADDR: u16 = 3;
    const NS_DNS_IPV6_ADDR: u16 = 4;
}

impl<'a> PcapNgOption<'a> for NameResolutionOption<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::NS_DNS_NAME => NameResolutionOption::NsDnsName(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::NS_DNS_IPV4_ADDR => {
                if slice.len() != 4 {
                    return Err(OptionEntryError::WrongSize { expected: 4, actual: slice.len() });
                }
                NameResolutionOption::NsDnsIpv4Addr(Cow::Borrowed(slice))
            },
            Self::NS_DNS_IPV6_ADDR => {
                if slice.len() != 16 {
                    return Err(OptionEntryError::WrongSize { expected: 16, actual: slice.len() });
                }
                NameResolutionOption::NsDnsIpv6Addr(Cow::Borrowed(slice))
            },
            _ => NameResolutionOption::Common(CommonOption::new::<B>(code, slice)?),
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
            NameResolutionOption::NsDnsName(a) => a.write_opt_to::<B, W>(Self::NS_DNS_NAME, writer),
            NameResolutionOption::NsDnsIpv4Addr(a) => a.write_opt_to::<B, W>(Self::NS_DNS_IPV4_ADDR, writer),
            NameResolutionOption::NsDnsIpv6Addr(a) => a.write_opt_to::<B, W>(Self::NS_DNS_IPV6_ADDR, writer),
            NameResolutionOption::Common(a) => a.write_opt_to::<B, W>(a.code(), writer),
        }
    }

    fn code_name(code: u16) -> &'static str {
        match code {
            Self::NS_DNS_NAME => "NsDnsName",
            Self::NS_DNS_IPV4_ADDR => "NsDnsIpv4Addr",
            Self::NS_DNS_IPV6_ADDR => "NsDnsIpv6Addr",
            _ => CommonOption::code_name(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use byteorder_slice::BigEndian;

    use super::{NameResolutionBlock, NameResolutionOption, PcapNgBlock};
    use crate::pcapng::PcapNgState;
    use crate::pcapng::errors::{ContentValidationError, PcapNgWriteError};

    #[test]
    fn write_rejects_oversized_name_resolution_option() {
        let block = NameResolutionBlock {
            records: vec![],
            options: vec![NameResolutionOption::NsDnsName(Cow::Owned("a".repeat(u16::MAX as usize + 1)))],
        };

        let error = block.write_to::<BigEndian, _>(&PcapNgState::default(), &mut Vec::new()).unwrap_err();

        assert!(matches!(
            error,
            PcapNgWriteError::Validation {
                field: "OptionEntry.length",
                source: ContentValidationError::OptionTooBig(len),
            } if len == u16::MAX as usize + 1
        ));
    }
}
