use crate::pcapng::blocks::common::{opts_from_slice, read_to_string, read_to_vec};
use crate::errors::PcapError;
use crate::DataLink;
use std::io::Read;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::peek_reader::PeekReader;
use std::borrow::Cow;

/// An Interface Description Block (IDB) is the container for information describing an interface
/// on which packet data is captured.
#[derive(Clone, Debug)]
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

    pub fn from_slice<B:ByteOrder>(mut slice: &'a[u8]) -> Result<(Self, &'a[u8]), PcapError> {

        if slice.len() < 16 {
            return Err(PcapError::IncompleteBuffer(16 - slice.len()));
        }

        let interface_id = slice.read_u32::<B>()? as u32;
        let timestamp = slice.read_u64::<B>()?;
        let (options, slice) = InterfaceStatisticsOption::from_slice::<B>(slice)?;

        let block = InterfaceStatisticsBlock {
            interface_id,
            timestamp,
            options
        };

        Ok((block, slice))
    }
}

#[derive(Clone, Debug)]
pub enum InterfaceStatisticsOption<'a> {

    /// The opt_comment option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment(&'a str),

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
}

impl<'a> InterfaceStatisticsOption<'a> {

    fn from_slice<B:ByteOrder>(slice: &'a[u8]) -> Result<(Vec<Self>, &'a[u8]), PcapError> {

        opts_from_slice::<B, _, _>(slice, |mut slice, type_, len| {

            let opt = match type_ {

                1 => InterfaceStatisticsOption::Comment(std::str::from_utf8(slice)?),
                2 => InterfaceStatisticsOption::IsbStartTime(slice.read_u64::<B>()?),
                3 => InterfaceStatisticsOption::IsbEndTime(slice.read_u64::<B>()?),
                4 => InterfaceStatisticsOption::IsbIfRecv(slice.read_u64::<B>()?),
                5 => InterfaceStatisticsOption::IsbIfDrop(slice.read_u64::<B>()?),
                6 => InterfaceStatisticsOption::IsbFilterAccept(slice.read_u64::<B>()?),
                7 => InterfaceStatisticsOption::IsbOsDrop(slice.read_u64::<B>()?),
                8 => InterfaceStatisticsOption::IsbUsrDeliv(slice.read_u64::<B>()?),

                _ => return Err(PcapError::InvalidField("InterfaceStatisticsOption type invalid"))
            };

            Ok(opt)
        })
    }
}

