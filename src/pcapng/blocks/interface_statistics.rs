use crate::pcapng::blocks::block_common::opts_from_slice;
use crate::errors::PcapError;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::pcapng::{UnknownOption, CustomUtf8Option, CustomBinaryOption};
use std::borrow::Cow;
use derive_into_owned::IntoOwned;


/// The Interface Statistics Block contains the capture statistics for a given interface and it is optional.
#[derive(Clone, Debug, IntoOwned)]
pub struct InterfaceStatisticsBlock<'a> {

    /// Specifies the interface these statistics refers to.
    /// The correct interface will be the one whose Interface Description Block (within the current Section of the file)
    /// is identified by same number of this field.
    pub interface_id: u32,

    /// Time this statistics refers to.
    /// The format of the timestamp is the same already defined in the Enhanced Packet Block.
    /// The length of a unit of time is specified by the 'if_tsresol' option of the Interface Description Block referenced by this packet.
    pub timestamp: u64,

    /// Options
    pub options: Vec<InterfaceStatisticsOption<'a>>
}

impl<'a> InterfaceStatisticsBlock<'a> {

    pub fn from_slice<B:ByteOrder>(mut slice: &'a[u8]) -> Result<(&'a[u8], Self), PcapError> {

        if slice.len() < 12 {
            return Err(PcapError::InvalidField("InterfaceStatisticsBlock: block length < 12"));
        }

        let interface_id = slice.read_u32::<B>()? as u32;
        let timestamp = slice.read_u64::<B>()?;
        let (slice, options) = InterfaceStatisticsOption::from_slice::<B>(slice)?;

        let block = InterfaceStatisticsBlock {
            interface_id,
            timestamp,
            options
        };

        Ok((slice, block))
    }
}

#[derive(Clone, Debug, IntoOwned)]
pub enum InterfaceStatisticsOption<'a> {

    /// The opt_comment option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment(Cow<'a, str>),

    /// The isb_starttime option specifies the time the capture started.
    IsbStartTime(u64),

    /// The isb_endtime option specifies the time the capture ended.
    IsbEndTime(u64),

    /// The isb_ifrecv option specifies the 64-bit unsigned integer number of packets received from the physical interface
    /// starting from the beginning of the capture.
    IsbIfRecv(u64),

    /// The isb_ifdrop option specifies the 64-bit unsigned integer number of packets dropped by the interface
    /// due to lack of resources starting from the beginning of the capture.
    IsbIfDrop(u64),

    /// The isb_filteraccept option specifies the 64-bit unsigned integer number of packets accepted
    /// by filter starting from the beginning of the capture.
    IsbFilterAccept(u64),

    /// The isb_osdrop option specifies the 64-bit unsigned integer number of packets dropped
    /// by the operating system starting from the beginning of the capture.
    IsbOsDrop(u64),

    /// The isb_usrdeliv option specifies the 64-bit unsigned integer number of packets delivered
    /// to the user starting from the beginning of the capture.
    IsbUsrDeliv(u64),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>)
}

impl<'a> InterfaceStatisticsOption<'a> {

    fn from_slice<B:ByteOrder>(slice: &'a[u8]) -> Result<(&'a [u8], Vec<Self>), PcapError> {

        opts_from_slice::<B, _, _>(slice, |mut slice, code, length| {

            let opt = match code {

                1 => InterfaceStatisticsOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
                2 => InterfaceStatisticsOption::IsbStartTime(slice.read_u64::<B>()?),
                3 => InterfaceStatisticsOption::IsbEndTime(slice.read_u64::<B>()?),
                4 => InterfaceStatisticsOption::IsbIfRecv(slice.read_u64::<B>()?),
                5 => InterfaceStatisticsOption::IsbIfDrop(slice.read_u64::<B>()?),
                6 => InterfaceStatisticsOption::IsbFilterAccept(slice.read_u64::<B>()?),
                7 => InterfaceStatisticsOption::IsbOsDrop(slice.read_u64::<B>()?),
                8 => InterfaceStatisticsOption::IsbUsrDeliv(slice.read_u64::<B>()?),

                2988 | 19372 => InterfaceStatisticsOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
                2989 | 19373 => InterfaceStatisticsOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

                _ => InterfaceStatisticsOption::Unknown(UnknownOption::new(code, length, slice))
            };

            Ok(opt)
        })
    }
}

