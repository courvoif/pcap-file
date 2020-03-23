use crate::pcapng::blocks::block_common::opts_from_slice;
use crate::errors::PcapError;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::pcapng::{CustomBinaryOption, CustomUtf8Option, UnknownOption};
use std::borrow::Cow;
use derive_into_owned::IntoOwned;


/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
#[derive(Clone, Debug, IntoOwned)]
pub struct NameResolutionBlock<'a> {

    /// Records
    pub records: Vec<Record<'a>>,

    /// Options
    pub options: Vec<NameResolutionOption<'a>>
}

impl<'a> NameResolutionBlock<'a> {

    pub fn from_slice<B:ByteOrder>(mut slice: &'a[u8]) -> Result<(&'a [u8], Self), PcapError> {

        let mut records = Vec::new();

        loop {
            let (slice_tmp, record) = Record::from_slice::<B>(slice)?;
            slice = slice_tmp;

            match record {
                Record::End => break,
                _ => records.push(record)
            }
        }

        let (rem, options) = NameResolutionOption::from_slice::<B>(slice)?;

        let block = NameResolutionBlock {
            records,
            options
        };

        Ok((rem, block))
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub enum Record<'a> {
    End,
    Ipv4(Ipv4Record<'a>),
    Ipv6(Ipv6Record<'a>),
    Unknown(UnknownRecord<'a>)
}

impl<'a> Record<'a> {

    pub fn from_slice<B:ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a[u8], Self), PcapError> {

        let type_ = slice.read_u16::<B>()?;
        let length = slice.read_u16::<B>()?;
        let pad_len = (4 - length % 4) % 4;

        if slice.len() < length as usize {
            return Err(PcapError::InvalidField("NameResolutionBlock: Record length > slice.len()"));
        }
        let value = &slice[..length as usize];

        let record = match type_ {
            0 => {
                if length != 0 {
                    return Err(PcapError::InvalidField("NameResolutionBlock: nrb_record_end length != 0"));
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
            _=> {
                let record = UnknownRecord::new(type_, length, value);
                Record::Unknown(record)
            }
        };

        let len = length as usize + pad_len as usize;

        Ok((&slice[len..], record))
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct Ipv4Record<'a> {
    pub ip_addr: Cow<'a, [u8]>,
    pub names: Vec<Cow<'a, str>>
}

impl<'a> Ipv4Record<'a> {

    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, PcapError> {

        if slice.len() < 6 as usize {
            return Err(PcapError::InvalidField("NameResolutionBlock: Ipv4Record len < 6"));
        }

        let ip_addr = &slice[..4];
        slice = &slice[4..];

        let mut names = vec![];
        while !slice.is_empty() {
            let (slice_tmp, name) = str_from_u8_null_terminated(slice)?;
            slice = slice_tmp;
            names.push(Cow::Borrowed(name));
        }

        let record = Ipv4Record {
            ip_addr: Cow::Borrowed(ip_addr),
            names
        };

        Ok(record)
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct Ipv6Record<'a> {
    pub ip_addr: Cow<'a, [u8]>,
    pub names: Vec<Cow<'a, str>>
}

impl<'a> Ipv6Record<'a> {

    pub fn from_slice(mut slice: &'a[u8]) -> Result<Self, PcapError> {

        if slice.len() < 18 as usize {
            return Err(PcapError::InvalidField("NameResolutionBlock: Ipv6Record len < 18"));
        }

        let ip_addr = &slice[..16];
        slice = &slice[16..];

        let mut names = vec![];
        while !slice.is_empty() {
            let (slice_tmp, name) = str_from_u8_null_terminated(slice)?;
            slice = slice_tmp;
            names.push(Cow::Borrowed(name));
        }

        let record = Ipv6Record {
            ip_addr: Cow::Borrowed(ip_addr),
            names
        };

        Ok(record)
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub struct UnknownRecord<'a> {
    pub type_: u16,
    pub length: u16,
    pub value: Cow<'a, [u8]>
}

impl<'a> UnknownRecord<'a> {

    fn new(type_: u16, length: u16, value: &'a[u8]) -> Self {
        UnknownRecord {
            type_,
            length,
            value: Cow::Borrowed(value)
        }
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub enum NameResolutionOption<'a> {
    /// The opt_comment option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment(Cow<'a, str>),

    /// The ns_dnsname option is a UTF-8 string containing the name of the machine (DNS server) used to perform the name resolution.
    NsDnsName(Cow<'a, str>),

    /// The ns_dnsIP4addr option specifies the IPv4 address of the DNS server.
    NsDnsIpv4Addr(Cow<'a, [u8]>),

    /// The ns_dnsIP6addr option specifies the IPv6 address of the DNS server.
    NsDnsIpv6Addr(Cow<'a, [u8]>),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>)
}


impl<'a> NameResolutionOption<'a> {

    fn from_slice<B:ByteOrder>(slice: &'a[u8]) -> Result<(&'a[u8], Vec<Self>), PcapError> {

        opts_from_slice::<B, _, _>(slice, |slice, code, length| {

            let opt = match code {

                1 => NameResolutionOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
                2 => NameResolutionOption::NsDnsName(Cow::Borrowed(std::str::from_utf8(slice)?)),
                3 => {
                    if slice.len() != 4 {
                        return Err(PcapError::InvalidField("NameResolutionOption: NsDnsIpv4Addr length != 4"))
                    }
                    NameResolutionOption::NsDnsIpv4Addr(Cow::Borrowed(slice))
                },
                4 => {
                    if slice.len() != 16 {
                        return Err(PcapError::InvalidField("NameResolutionOption: NsDnsIpv6Addr length != 16"))
                    }
                    NameResolutionOption::NsDnsIpv6Addr(Cow::Borrowed(slice))
                },

                2988 | 19372 => NameResolutionOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
                2989 | 19373 => NameResolutionOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

                _ => NameResolutionOption::Unknown(UnknownOption::new(code, length, slice))
            };

            Ok(opt)
        })
    }
}

pub fn str_from_u8_null_terminated(src: &[u8]) -> Result<(&[u8], &str), PcapError> {
    let nul_pos = src.iter()
        .position(|&c| c == b'\0')
        .ok_or(PcapError::InvalidField("Non null terminated string"))?;

    let s = std::str::from_utf8(&src[0..nul_pos])?;

    let rem = &src[nul_pos..];
    let rem = if rem.len() == 1 {
        &[]
    }
    else {
        &rem[1..]
    };

    Ok((rem, s))
}

