//! [`Name Resolution Block`](NameResolutionBlock).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::{Error as IoError, ErrorKind, Result as IoResult, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

pub use macaddr::{MacAddr6, MacAddr8};

use super::block_common::{Block, PcapNgBlock, checked_body_len};
use super::opt_common::{
    CommonOption, PcapNgOption, check_opt_len, opts_from_slice, validate_opts, validate_unique_opts,
    write_bytes_option, write_opts_to,
};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, OptionEntryError, WriteError};

/* ----- NameResolutionBlock ----- */

/// Associates network addresses with their resolved names.
/// Records can be repeated, and no interface is required.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct NameResolutionBlock<'a> {
    /// Name-resolution records, excluding the end marker.
    /// The writer appends exactly one end marker automatically.
    pub records: Vec<Record<'a>>,
    /// DNS server metadata and common block options.
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

    /// Writes this block body using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        let mut len = 0;

        for record in &self.records {
            len = checked_body_len(len, record.write_to::<B, _>(writer)?).map_err(WriteError::Other)?;
        }
        // The terminator is framing, not a decoded record.
        writer.write_u16::<B>(0)?;
        writer.write_u16::<B>(0)?;
        len = checked_body_len(len, 4).map_err(WriteError::Other)?;

        let opt_len = write_opts_to::<B, _, _>(&self.options, state, None, writer)
            .map_err(|error| error.map_other(BlockValidationError::Option))?;
        len = checked_body_len(len, opt_len).map_err(WriteError::Other)?;

        Ok(len)
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

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::NameResolution(self)
    }
}

/* ----- Record ----- */

/// Address-to-name records carried by a [`NameResolutionBlock`].
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Record<'a> {
    /// IPv4 address and names.
    Ipv4(Ipv4Record<'a>),
    /// IPv6 address and names.
    Ipv6(Ipv6Record<'a>),
    /// EUI-48 address and names (record type `3`).
    Eui48(Eui48Record<'a>),
    /// EUI-64 address and names (record type `4`).
    Eui64(Eui64Record<'a>),
    /// Preserved content for an unsupported record type.
    Unknown(UnknownRecord<'a>),
}

impl<'a> Record<'a> {
    /// Validates names and the encoded record size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes for known address records.
    /// Keep each encoded value within `u16::MAX` bytes and unknown record codes above `4`.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        match self {
            Self::Ipv4(record) => record.validate(),
            Self::Ipv6(record) => record.validate(),
            Self::Eui48(record) => record.validate(),
            Self::Eui64(record) => record.validate(),
            Self::Unknown(record) => {
                u16::try_from(record.value.len()).map_err(|_| BlockValidationError::RecordTooLarge {
                    actual: record.value.len(),
                    maximum: u16::MAX as usize,
                })?;
                // Known record encodings include the terminator at code 0.
                if record.type_ <= 4 {
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
    /// Supply complete record bytes and NUL-terminated UTF-8 names for known address records.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Option<Self>), BlockValidationError> {
        if slice.len() < 4 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 4,
                actual: slice.len(),
            });
        }

        let type_ = slice.read_u16::<B>().expect("record header length checked above");
        let length = slice.read_u16::<B>().expect("record header length checked above") as usize;
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

                return Ok((slice, None));
            }
            1 => Record::Ipv4(Ipv4Record::from_slice(value)?),
            2 => Record::Ipv6(Ipv6Record::from_slice(value)?),
            3 => Record::Eui48(Eui48Record::from_slice(value)?),
            4 => Record::Eui64(Eui64Record::from_slice(value)?),
            _ => Record::Unknown(UnknownRecord::new(type_, value)),
        };

        Ok((&slice[length + pad_len..], Some(record)))
    }

    /// Writes a framed record, including its type, length, and alignment padding.
    /// Call [`Self::validate`] first to check names and unknown type codes.
    ///
    /// # Errors
    /// Reduce oversized record values before retrying; encoding failures leave the output unchanged.
    /// An I/O failure can leave a partial record in the output.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> Result<usize, WriteError<BlockValidationError>> {
        let (type_, len) = match self {
            Self::Ipv4(record) => (1, record_value_len(4, &record.names)),
            Self::Ipv6(record) => (2, record_value_len(16, &record.names)),
            Self::Eui48(record) => (3, record_value_len(6, &record.names)),
            Self::Eui64(record) => (4, record_value_len(8, &record.names)),
            Self::Unknown(record) => {
                if record.type_ == 0 {
                    return Err(WriteError::Other(BlockValidationError::RecordTypeInvalid(record.type_)));
                }
                (record.type_, Ok(record.value.len()))
            }
        };
        let len = len.map_err(WriteError::Other)?;
        let encoded_len = u16::try_from(len).map_err(|_| {
            WriteError::Other(BlockValidationError::RecordTooLarge {
                actual: len,
                maximum: u16::MAX as usize,
            })
        })?;
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(type_)?;
        writer.write_u16::<B>(encoded_len)?;
        match self {
            Self::Ipv4(record) => {
                record.write_to::<B, _>(writer)?;
            }
            Self::Ipv6(record) => {
                record.write_to::<B, _>(writer)?;
            }
            Self::Eui48(record) => {
                record.write_to::<B, _>(writer)?;
            }
            Self::Eui64(record) => {
                record.write_to::<B, _>(writer)?;
            }
            Self::Unknown(record) => writer.write_all(&record.value)?,
        }
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(4 + len + pad_len)
    }
}

/* ----- Ipv4Record ----- */

/// IPv4 address and names carried by a Name Resolution record.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv4Record<'a> {
    /// Address in network octet order.
    pub ip_addr: Ipv4Addr,
    /// Nonempty UTF-8 names for this address, without embedded NUL bytes.
    /// Non-strict decoding preserves empty names; [`Self::validate`] rejects them.
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv4Record<'a> {
    /// Validates names and their total encoded size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes.
    /// Keep the address and NUL-terminated names within `u16::MAX` encoded bytes.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        validate_record_names(4, &self.names)
    }

    /// Decodes an IPv4 address and its names from an unframed record value.
    /// Call [`Self::validate`] to check the decoded names.
    ///
    /// # Errors
    /// Supply a complete address and NUL-terminated UTF-8 names.
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockValidationError> {
        if slice.len() < 4 {
            return Err(BlockValidationError::RecordWrongMinSize {
                min: 4,
                actual: slice.len(),
            });
        }

        let address: [u8; 4] = slice
            .read_slice(4)
            .expect("address length checked above")
            .try_into()
            .expect("address length checked above");
        let ip_addr = Ipv4Addr::from_octets(address);
        let names = record_names_from_slice(slice)?;

        Ok(Self { ip_addr, names })
    }

    /// Writes the address and NUL-terminated names without record framing or padding.
    /// Call [`Self::validate`] before writing manually constructed names.
    ///
    /// # Errors
    /// Keep the encoded value within `u16::MAX` bytes.
    /// An I/O failure can leave a partial record in the output.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        write_record_value(writer, &self.ip_addr.octets(), &self.names)
    }
}

/* ----- Ipv6Record ----- */

/// IPv6 address and names carried by a Name Resolution record.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv6Record<'a> {
    /// Address in network octet order.
    pub ip_addr: Ipv6Addr,
    /// Nonempty UTF-8 names for this address, without embedded NUL bytes.
    /// Non-strict decoding preserves empty names; [`Self::validate`] rejects them.
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv6Record<'a> {
    /// Validates names and their total encoded size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes.
    /// Keep the address and NUL-terminated names within `u16::MAX` encoded bytes.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        validate_record_names(16, &self.names)
    }

    /// Decodes an IPv6 address and its names from an unframed record value.
    /// Call [`Self::validate`] to check the decoded names.
    ///
    /// # Errors
    /// Supply a complete address and NUL-terminated UTF-8 names.
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockValidationError> {
        if slice.len() < 16 {
            return Err(BlockValidationError::RecordWrongMinSize {
                min: 16,
                actual: slice.len(),
            });
        }

        let address: [u8; 16] = slice
            .read_slice(16)
            .expect("address length checked above")
            .try_into()
            .expect("address length checked above");
        let ip_addr = Ipv6Addr::from_octets(address);
        let names = record_names_from_slice(slice)?;

        Ok(Self { ip_addr, names })
    }

    /// Writes the address and NUL-terminated names without record framing or padding.
    /// Call [`Self::validate`] before writing manually constructed names.
    ///
    /// # Errors
    /// Keep the encoded value within `u16::MAX` bytes.
    /// An I/O failure can leave a partial record in the output.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        write_record_value(writer, &self.ip_addr.octets(), &self.names)
    }
}

/* ----- Eui48Record ----- */

/// EUI-48 address and names carried by a Name Resolution record.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Eui48Record<'a> {
    /// Address in network octet order.
    pub eui_addr: MacAddr6,
    /// Nonempty UTF-8 names for this address, without embedded NUL bytes.
    /// Non-strict decoding preserves empty names; [`Self::validate`] rejects them.
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Eui48Record<'a> {
    /// Validates names and their total encoded size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes.
    /// Keep the address and NUL-terminated names within `u16::MAX` encoded bytes.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        validate_record_names(6, &self.names)
    }

    /// Decodes an EUI-48 address and its names from an unframed record value.
    /// Call [`Self::validate`] to check the decoded names.
    ///
    /// # Errors
    /// Supply a complete address and NUL-terminated UTF-8 names.
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockValidationError> {
        if slice.len() < 6 {
            return Err(BlockValidationError::RecordWrongMinSize {
                min: 6,
                actual: slice.len(),
            });
        }

        let address: [u8; 6] = slice
            .read_slice(6)
            .expect("address length checked above")
            .try_into()
            .expect("address length checked above");
        let eui_addr = MacAddr6::from(address);
        let names = record_names_from_slice(slice)?;

        Ok(Self { eui_addr, names })
    }

    /// Writes the address and NUL-terminated names without record framing or padding.
    /// Call [`Self::validate`] before writing manually constructed names.
    ///
    /// # Errors
    /// Keep the encoded value within `u16::MAX` bytes.
    /// An I/O failure can leave a partial record in the output.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        write_record_value(writer, self.eui_addr.as_bytes(), &self.names)
    }
}

/* ----- Eui64Record ----- */

/// EUI-64 address and names carried by a Name Resolution record.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Eui64Record<'a> {
    /// Address in network octet order.
    pub eui_addr: MacAddr8,
    /// Nonempty UTF-8 names for this address, without embedded NUL bytes.
    /// Non-strict decoding preserves empty names; [`Self::validate`] rejects them.
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Eui64Record<'a> {
    /// Validates names and their total encoded size.
    ///
    /// # Errors
    /// Use at least one nonempty name without embedded NUL bytes.
    /// Keep the address and NUL-terminated names within `u16::MAX` encoded bytes.
    pub fn validate(&self) -> Result<(), BlockValidationError> {
        validate_record_names(8, &self.names)
    }

    /// Decodes an EUI-64 address and its names from an unframed record value.
    /// Call [`Self::validate`] to check the decoded names.
    ///
    /// # Errors
    /// Supply a complete address and NUL-terminated UTF-8 names.
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, BlockValidationError> {
        if slice.len() < 8 {
            return Err(BlockValidationError::RecordWrongMinSize {
                min: 8,
                actual: slice.len(),
            });
        }

        let address: [u8; 8] = slice
            .read_slice(8)
            .expect("address length checked above")
            .try_into()
            .expect("address length checked above");
        let eui_addr = MacAddr8::from(address);
        let names = record_names_from_slice(slice)?;

        Ok(Self { eui_addr, names })
    }

    /// Writes the address and NUL-terminated names without record framing or padding.
    /// Call [`Self::validate`] before writing manually constructed names.
    ///
    /// # Errors
    /// Keep the encoded value within `u16::MAX` bytes.
    /// An I/O failure can leave a partial record in the output.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        write_record_value(writer, self.eui_addr.as_bytes(), &self.names)
    }
}

/* ----- Record helpers ----- */

/// Returns every NUL-terminated UTF-8 name, preserving empty entries for validation.
fn record_names_from_slice(slice: &[u8]) -> Result<Vec<Cow<'_, str>>, BlockValidationError> {
    if slice.is_empty() {
        return Ok(Vec::new());
    }

    // Remove only the final terminator; internal empty names must remain visible.
    let names = slice
        .strip_suffix(&[0])
        .ok_or(BlockValidationError::RecordNameUnterminated)?;
    names
        .split(|&byte| byte == 0)
        .map(|name| {
            std::str::from_utf8(name)
                .map(Cow::Borrowed)
                .map_err(BlockValidationError::RecordNameNotUtf8)
        })
        .collect()
}

/// Checks that address records contain nonempty names and fit their encoded length field.
fn validate_record_names(address_len: usize, names: &[Cow<'_, str>]) -> Result<(), BlockValidationError> {
    if names.is_empty() {
        return Err(BlockValidationError::RecordNamesEmpty);
    }
    for name in names {
        if name.is_empty() || name.as_bytes().contains(&0) {
            return Err(BlockValidationError::RecordNameInvalid);
        }
    }

    record_value_len(address_len, names)?;
    Ok(())
}

/// Returns the encoded address-and-names length, rejecting values above `u16::MAX`.
fn record_value_len(address_len: usize, names: &[Cow<'_, str>]) -> Result<usize, BlockValidationError> {
    let mut len = address_len;
    for name in names {
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
    Ok(len)
}

/// Writes address octets and terminated names after checking their encoded size.
fn write_record_value<W: Write>(writer: &mut W, address: &[u8], names: &[Cow<'_, str>]) -> IoResult<usize> {
    let len = record_value_len(address.len(), names).map_err(|error| IoError::new(ErrorKind::InvalidInput, error))?;
    writer.write_all(address)?;
    for name in names {
        writer.write_all(name.as_bytes())?;
        writer.write_u8(0)?;
    }
    Ok(len)
}

/* ----- UnknownRecord ----- */

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
