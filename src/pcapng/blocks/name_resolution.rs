use crate::pcapng::blocks::common::{opts_from_slice, read_to_string, read_to_vec};
use crate::errors::PcapError;
use crate::DataLink;
use std::io::Read;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::peek_reader::PeekReader;
use std::borrow::Cow;

/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
#[derive(Clone, Debug)]
pub struct NameResolutionBlock<'a> {

    /// Records
    pub records: Vec<Record<'a>>,

    /// Options
    pub options: Vec<NameResolutionOption<'a>>
}

impl<'a> NameResolutionBlock<'a> {

    pub fn from_slice<B:ByteOrder>(mut slice: &'a[u8]) -> Result<(Self, &'a[u8]), PcapError> {

        let mut records = Vec::new();

        loop {
            let (mut record, slice_tmp) = Record::from_slice::<B>(slice)?;
            slice = slice_tmp;

            if record.type_ == 0 {
                if record.length != 0 {
                    return Err(PcapError::InvalidField("NameResolutionBlock: nrb_record_end length != 0"));
                }

                break;
            }

            records.push(record);
        }

        let (options, slice) = NameResolutionOption::from_slice::<B>(slice)?;

        let block = NameResolutionBlock {
            records,
            options
        };

        Ok((block, slice))
    }
}

#[derive(Clone, Debug)]
pub struct Record<'a> {
    pub type_: u16,
    pub length: u16,
    pub value: &'a[u8]
}

impl<'a> Record<'a> {

    pub fn from_slice<B:ByteOrder>(mut slice: &'a[u8]) -> Result<(Self, &'a[u8]), PcapError> {

        let type_ = slice.read_u16::<B>()?;
        let length = slice.read_u16::<B>()?;

        if slice.len() < length as usize {
            return Err(PcapError::IncompleteBuffer(length as usize - slice.len()));
        }
        let value = &slice[..length as usize];

        let record = Record {
            type_,
            length,
            value
        };

        Ok((record, &slice[length as usize..]))
    }
}

#[derive(Clone, Debug)]
pub enum NameResolutionOption<'a> {
    /// The opt_comment option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment(&'a str),

    /// The ns_dnsname option is a UTF-8 string containing the name of the machine (DNS server) used to perform the name resolution.
    NsDnsName(&'a str),

    /// The ns_dnsIP4addr option specifies the IPv4 address of the DNS server.
    NsDnsIpv4Addr(&'a [u8]),

    /// The ns_dnsIP6addr option specifies the IPv6 address of the DNS server.
    NsDnsIpv6Addr(&'a [u8])
}


impl<'a> NameResolutionOption<'a> {

    fn from_slice<B:ByteOrder>(slice: &'a[u8]) -> Result<(Vec<Self>, &'a[u8]), PcapError> {

        opts_from_slice::<B, _, _>(slice, |mut slice, type_, len| {

            let opt = match type_ {

                1 => NameResolutionOption::Comment(std::str::from_utf8(slice)?),
                2 => NameResolutionOption::NsDnsName(std::str::from_utf8(slice)?),
                3 => {
                    if slice.len() != 4 {
                        return Err(PcapError::InvalidField("NameResolutionOption: NsDnsIpv4Addr length != 4"))
                    }
                    NameResolutionOption::NsDnsIpv4Addr(slice)
                },
                4 => {
                    if slice.len() != 16 {
                        return Err(PcapError::InvalidField("NameResolutionOption: NsDnsIpv6Addr length != 16"))
                    }
                    NameResolutionOption::NsDnsIpv6Addr(slice)
                },

                _ => return Err(PcapError::InvalidField("InterfaceDescriptionOption type invalid"))
            };

            Ok(opt)
        })
    }
}
