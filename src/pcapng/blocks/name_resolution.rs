//! Name Resolution Block (NRB).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::{Result as IoResult, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{
    CommonOption, PcapNgOption, check_opt_len, opts_from_slice, validate_opts, validate_unique_opts,
    write_bytes_option, write_opts_to,
};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, OptionEntryError, WriteError};

/* ----- NameResolutionBlock ----- */

/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct NameResolutionBlock<'a> {
    /// Name-resolution records, excluding the end marker.
    /// The writer appends exactly one end marker automatically.
    pub records: Vec<Record<'a>>,
    /// Options
    pub options: Vec<NameResolutionOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for NameResolutionBlock<'a> {
    /// Numeric type code of this block.
    const TYPE: u32 = 0x00000004;
    /// Human-readable name of this block.
    const NAME: &'static str = "Name Resolution Block";
    /// Decodes this block body using the supplied section state.
    fn from_body<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError> {
        let mut records = Vec::new();

        loop {
            let (slice_tmp, record) = Record::from_slice::<B>(slice)?;
            slice = slice_tmp;

            match record {
                None => break,
                Some(record) => records.push(record),
            }
        }

        let (rem, options) = opts_from_slice::<B, NameResolutionOption>(state, None, slice)?;

        let block = NameResolutionBlock { records, options };

        Ok((rem, block))
    }

    /// Checks the constraints applicable to this value.
    fn validate(&self, state: &PcapNgState) -> Result<(), BlockValidationError> {
        for record in &self.records {
            record.validate()?;
        }

        validate_unique_opts(&self.options, |option| {
            !matches!(option, NameResolutionOption::Common(_))
        })
        .map_err(BlockValidationError::Option)?;

        validate_opts(&self.options, state, None).map_err(BlockValidationError::Option)
    }

    /// Writes this block body using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        let mut len = 0;

        for record in &self.records {
            len += record.write_to::<B, _>(writer)?;
        }
        // The terminator is framing, not a decoded record.
        writer.write_u16::<B>(0)?;
        writer.write_u16::<B>(0)?;
        len += 4;

        len += write_opts_to::<B, _, _>(&self.options, state, None, writer)
            .map_err(|error| error.map_other(BlockValidationError::Option))?;

        Ok(len)
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::NameResolution(self)
    }
}

/// Resolution block record types
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Record<'a> {
    /// IPv4 address and names carried by a Name Resolution record.
    Ipv4(Ipv4Record<'a>),
    /// IPv6 address and names carried by a Name Resolution record.
    Ipv6(Ipv6Record<'a>),
    /// Unknown records
    Unknown(UnknownRecord<'a>),
}

impl<'a> Record<'a> {
    /// Validates names and the encoded record size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes for known address records.
    /// Keep each encoded value within `u16::MAX` bytes and unknown record codes above `2`.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        match self {
            Self::Ipv4(record) => record.validate(),
            Self::Ipv6(record) => record.validate(),
            Self::Unknown(record) => {
                u16::try_from(record.value.len()).map_err(|_| BlockValidationError::RecordTooLarge {
                    actual: record.value.len(),
                    maximum: u16::MAX as usize,
                })?;
                // Codes 0, 1 and 2 have known encodings; in particular 0 is the terminator.
                if record.type_ <= 2 {
                    return Err(BlockValidationError::RecordTypeInvalid(record.type_));
                }
                Ok(())
            }
        }
    }

    /// Returns a framed record and the remaining input, or `None` for the end marker.
    /// Semantic validation is left to the caller.
    ///
    /// # Errors
    /// Supply complete record bytes and valid UTF-8 names for known address records.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Option<Self>), BlockValidationError> {
        if slice.len() < 4 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 4,
                actual: slice.len(),
            });
        }

        let type_ = slice.read_u16::<B>().unwrap();
        let length = slice.read_u16::<B>().unwrap() as usize;
        let pad_len = (4 - length % 4) % 4;

        if slice.len() < length + pad_len {
            return Err(BlockValidationError::ContentTooSmall {
                needed: length + pad_len,
                actual: slice.len(),
            });
        }
        let value = &slice[..length];

        let record = match type_ {
            0 => {
                if length != 0 {
                    return Err(BlockValidationError::RecordWrongSize {
                        expected: 0,
                        actual: length,
                    });
                }

                return Ok((&slice[length + pad_len..], None));
            }

            1 => {
                let record = Ipv4Record::from_slice(value)?;
                Record::Ipv4(record)
            }

            2 => {
                let record = Ipv6Record::from_slice(value)?;
                Record::Ipv6(record)
            }

            _ => {
                let record = UnknownRecord::new(type_, value);
                Record::Unknown(record)
            }
        };

        let len = length + pad_len;

        Ok((&slice[len..], Some(record)))
    }

    /// Writes a framed record, including its type, length, and alignment padding.
    /// Call [`Self::validate`] first to check names and unknown type codes.
    ///
    /// # Errors
    /// An I/O failure can leave a partial record in the output.
    /// Use [`Self::validate`] to reject invalid values before writing.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> Result<usize, WriteError<BlockValidationError>> {
        match self {
            Record::Ipv4(a) => {
                let len = a.write_to::<B, _>(&mut std::io::sink())?;
                let pad_len = (4 - len % 4) % 4;

                let len: u16 = len.try_into().map_err(|_| {
                    WriteError::Other(BlockValidationError::RecordTooLarge {
                        actual: len,
                        maximum: u16::MAX as usize,
                    })
                })?;

                writer.write_u16::<B>(1)?;
                writer.write_u16::<B>(len)?;
                a.write_to::<B, _>(writer)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len as usize + pad_len)
            }
            Record::Ipv6(a) => {
                let len = a.write_to::<B, _>(&mut std::io::sink())?;
                let pad_len = (4 - len % 4) % 4;

                let len: u16 = len.try_into().map_err(|_| {
                    WriteError::Other(BlockValidationError::RecordTooLarge {
                        actual: len,
                        maximum: u16::MAX as usize,
                    })
                })?;

                writer.write_u16::<B>(2)?;
                writer.write_u16::<B>(len)?;
                a.write_to::<B, _>(writer)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len as usize + pad_len)
            }
            Record::Unknown(a) => {
                if a.type_ == 0 {
                    return Err(WriteError::Other(BlockValidationError::RecordTypeInvalid(a.type_)));
                }
                let len = a.value.len();
                let pad_len = (4 - len % 4) % 4;

                let len: u16 = len.try_into().map_err(|_| {
                    WriteError::Other(BlockValidationError::RecordTooLarge {
                        actual: len,
                        maximum: u16::MAX as usize,
                    })
                })?;

                writer.write_u16::<B>(a.type_)?;
                writer.write_u16::<B>(len)?;
                writer.write_all(&a.value)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len as usize + pad_len)
            }
        }
    }
}

/// IPv4 address and names carried by a Name Resolution record.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv4Record<'a> {
    /// IPv4 Addr
    pub ip_addr: Ipv4Addr,
    /// Nonempty UTF-8 names for this address, without embedded NUL bytes.
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv4Record<'a> {
    /// Validates names and their total encoded size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes.
    /// Keep the address and NUL-terminated names within `u16::MAX` encoded bytes.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        if self.names.is_empty() {
            return Err(BlockValidationError::RecordNamesEmpty);
        }
        let mut len = 4_usize;
        for name in &self.names {
            if name.is_empty() || name.as_bytes().contains(&0) {
                return Err(BlockValidationError::RecordNameInvalid);
            }
            len = len.checked_add(name.len()).and_then(|len| len.checked_add(1)).ok_or(
                BlockValidationError::RecordTooLarge {
                    actual: usize::MAX,
                    maximum: u16::MAX as usize,
                },
            )?;
        }
        u16::try_from(len).map_err(|_| BlockValidationError::RecordTooLarge {
            actual: len,
            maximum: u16::MAX as usize,
        })?;
        Ok(())
    }

    /// Decodes an IPv4 address and its names from an unframed record value.
    /// Call [`Self::validate`] to check the decoded names.
    ///
    /// # Errors
    /// Supply complete record bytes and valid UTF-8 names for known address records.
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockValidationError> {
        if slice.len() < 4 {
            return Err(BlockValidationError::RecordWrongMinSize {
                min: 4,
                actual: slice.len(),
            });
        }

        let ip_addr_oct: [u8; 4] = slice.read_slice(4).unwrap().try_into().unwrap();
        let ip_addr = Ipv4Addr::from_octets(ip_addr_oct);

        let mut names = vec![];
        for name in slice.split(|&b| b == 0) {
            if name.is_empty() {
                break;
            }
            names.push(Cow::Borrowed(
                std::str::from_utf8(name).map_err(BlockValidationError::RecordNameNotUtf8)?,
            ));
        }

        let record = Ipv4Record { ip_addr, names };

        Ok(record)
    }

    /// Writes the address and NUL-terminated names without record framing or padding.
    /// Call [`Self::validate`] before writing manually constructed names.
    ///
    /// # Errors
    /// An I/O failure can leave a partial record in the output.
    /// Use [`Self::validate`] to reject invalid values before writing.
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

/// IPv6 address and names carried by a Name Resolution record.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv6Record<'a> {
    /// Ipv6 addr
    pub ip_addr: Ipv6Addr,
    /// Nonempty UTF-8 names for this address, without embedded NUL bytes.
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv6Record<'a> {
    /// Validates names and their total encoded size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes.
    /// Keep the address and NUL-terminated names within `u16::MAX` encoded bytes.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        if self.names.is_empty() {
            return Err(BlockValidationError::RecordNamesEmpty);
        }
        let mut len = 16_usize;
        for name in &self.names {
            if name.is_empty() || name.as_bytes().contains(&0) {
                return Err(BlockValidationError::RecordNameInvalid);
            }
            len = len.checked_add(name.len()).and_then(|len| len.checked_add(1)).ok_or(
                BlockValidationError::RecordTooLarge {
                    actual: usize::MAX,
                    maximum: u16::MAX as usize,
                },
            )?;
        }
        u16::try_from(len).map_err(|_| BlockValidationError::RecordTooLarge {
            actual: len,
            maximum: u16::MAX as usize,
        })?;
        Ok(())
    }

    /// Decodes an IPv6 address and its names from an unframed record value.
    /// Call [`Self::validate`] to check the decoded names.
    ///
    /// # Errors
    /// Supply complete record bytes and valid UTF-8 names for known address records.
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockValidationError> {
        if slice.len() < 16 {
            return Err(BlockValidationError::RecordWrongMinSize {
                min: 16,
                actual: slice.len(),
            });
        }

        let ip_addr_oct: [u8; 16] = slice.read_slice(16).unwrap().try_into().unwrap();
        let ip_addr = Ipv6Addr::from_octets(ip_addr_oct);

        let mut names = vec![];
        for name in slice.split(|&b| b == 0) {
            if name.is_empty() {
                break;
            }
            names.push(Cow::Borrowed(
                std::str::from_utf8(name).map_err(BlockValidationError::RecordNameNotUtf8)?,
            ));
        }

        let record = Ipv6Record { ip_addr, names };

        Ok(record)
    }

    /// Writes the address and NUL-terminated names without record framing or padding.
    /// Call [`Self::validate`] before writing manually constructed names.
    ///
    /// # Errors
    /// An I/O failure can leave a partial record in the output.
    /// Use [`Self::validate`] to reject invalid values before writing.
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
        UnknownRecord {
            type_,
            value: Cow::Borrowed(value),
        }
    }
}

/* ----- NameResolutionOption ----- */

/// The Name Resolution Block (NRB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum NameResolutionOption<'a> {
    /// The ns_dnsname option is a UTF-8 string containing the name of the machine (DNS server) used to perform the name resolution.
    NsDnsName(Cow<'a, str>),

    /// The ns_dnsIP4addr option specifies the IPv4 address of the DNS server.
    NsDnsIpv4Addr(Ipv4Addr),

    /// The ns_dnsIP6addr option specifies the IPv6 address of the DNS server.
    NsDnsIpv6Addr(Ipv6Addr),

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl NameResolutionOption<'_> {
    /// Encoded option code for `NS_DNS_NAME`.
    const NS_DNS_NAME: u16 = 2;
    /// Encoded option code for `NS_DNS_IPV4_ADDR`.
    const NS_DNS_IPV4_ADDR: u16 = 3;
    /// Encoded option code for `NS_DNS_IPV6_ADDR`.
    const NS_DNS_IPV6_ADDR: u16 = 4;
}

impl<'a> PcapNgOption<'a> for NameResolutionOption<'a> {
    /// Decodes an option value for the supplied option code.
    fn from_content<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::NS_DNS_NAME => NameResolutionOption::NsDnsName(Cow::Borrowed(std::str::from_utf8(slice)?)),
            Self::NS_DNS_IPV4_ADDR => {
                check_opt_len(slice, 4)?;
                let ip: [u8; 4] = slice.try_into().expect("slice length checked above");
                NameResolutionOption::NsDnsIpv4Addr(Ipv4Addr::from(ip))
            }
            Self::NS_DNS_IPV6_ADDR => {
                check_opt_len(slice, 16)?;
                let ip: [u8; 16] = slice.try_into().expect("slice length checked above");
                NameResolutionOption::NsDnsIpv6Addr(Ipv6Addr::from(ip))
            }
            _ => NameResolutionOption::Common(CommonOption::from_content::<B>(code, slice)?),
        };

        Ok(opt)
    }

    /// Writes this value using the selected byte order.
    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        match self {
            NameResolutionOption::NsDnsName(a) => write_bytes_option::<B, W>(writer, Self::NS_DNS_NAME, a.as_bytes()),
            NameResolutionOption::NsDnsIpv4Addr(a) => {
                write_bytes_option::<B, W>(writer, Self::NS_DNS_IPV4_ADDR, &a.octets())
            }
            NameResolutionOption::NsDnsIpv6Addr(a) => {
                write_bytes_option::<B, W>(writer, Self::NS_DNS_IPV6_ADDR, &a.octets())
            }
            NameResolutionOption::Common(a) => a.write_to::<B, W>(writer),
        }
    }

    /// Checks the constraints applicable to this value.
    fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError> {
        Ok(())
    }

    /// Returns the encoded option code.
    fn code(&self) -> u16 {
        match self {
            Self::NsDnsName(_) => Self::NS_DNS_NAME,
            Self::NsDnsIpv4Addr(_) => Self::NS_DNS_IPV4_ADDR,
            Self::NsDnsIpv6Addr(_) => Self::NS_DNS_IPV6_ADDR,
            Self::Common(option) => option.code(),
        }
    }

    /// Returns the option name for its code.
    fn name(code: u16) -> &'static str {
        match code {
            Self::NS_DNS_NAME => "NsDnsName",
            Self::NS_DNS_IPV4_ADDR => "NsDnsIpv4Addr",
            Self::NS_DNS_IPV6_ADDR => "NsDnsIpv6Addr",
            _ => CommonOption::code_name(code),
        }
    }
}

/* ----- Tests ----- */

/// Checks this module's capture behavior.
#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use std::borrow::Cow;

    use byteorder_slice::BigEndian;

    use super::{NameResolutionBlock, NameResolutionOption, PcapNgBlock};
    use crate::pcapng::PcapNgState;
    use crate::pcapng::errors::{BlockValidationError, OptionEntryError, OptionError, WriteError};
    /* ----- Option validation ----- */

    /// Checks that oversized Name Resolution option values return errors.
    #[test]
    fn write_rejects_oversized_name_resolution_option() {
        let block = NameResolutionBlock {
            records: vec![],
            options: vec![NameResolutionOption::NsDnsName(Cow::Owned(
                "a".repeat(u16::MAX as usize + 1),
            ))],
        };

        let error = block
            .write_body_to::<BigEndian, _>(&PcapNgState::default(), &mut Vec::new())
            .unwrap_err();

        assert!(matches!(
            error,
            WriteError::Other(BlockValidationError::Option(OptionError {
                source,
                ..
            })) if matches!(source.as_ref(), OptionEntryError::TooLarge { actual, maximum }
                if *actual == u16::MAX as usize + 1 && *maximum == u16::MAX as usize)
        ));
    }
}
