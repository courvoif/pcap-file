//! Interface Statistics Block.

use std::io::Write;
use std::time::Duration;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::ByteOrder;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOptTo};
use crate::errors::PcapError;
use crate::pcapng::PcapNgState;


/// The Interface Statistics Block contains the capture statistics for a given interface and it is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct InterfaceStatisticsBlock<'a> {
    /// Specifies the interface these statistics refers to.
    /// 
    /// The correct interface will be the one whose Interface Description Block (within the current Section of the file)
    /// is identified by same number of this field.
    pub interface_id: u32,

    /// Time this statistics refers to.
    pub timestamp: Duration,

    /// Options
    pub options: Vec<InterfaceStatisticsOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for InterfaceStatisticsBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 12 {
            return Err(PcapError::InvalidField("InterfaceStatisticsBlock: block length < 12"));
        }

        let interface_id = slice.read_u32::<B>().unwrap();
        let timestamp = state.decode_timestamp::<B>(interface_id, &mut slice)?;
        let (slice, options) = InterfaceStatisticsOption::opts_from_slice::<B>(state, Some(interface_id), slice)?;

        let block = InterfaceStatisticsBlock { interface_id, timestamp, options };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapError> {
        writer.write_u32::<B>(self.interface_id)?;
        state.encode_timestamp::<B, W>(self.interface_id, self.timestamp, writer)?;

        let opt_len = InterfaceStatisticsOption::write_opts_to::<B, _>(&self.options, state, Some(self.interface_id), writer)?;
        Ok(12 + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::InterfaceStatistics(self)
    }
}


/// The Interface Statistics Block options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum InterfaceStatisticsOption<'a> {
    /// The isb_starttime option specifies the time the capture started.
    ///
    /// The time is relative to 1970-01-01 00:00:00 UTC.
    IsbStartTime(Duration),

    /// The isb_endtime option specifies the time the capture ended.
    ///
    /// The time is relative to 1970-01-01 00:00:00 UTC.
    IsbEndTime(Duration),

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

    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl<'a> PcapNgOption<'a> for InterfaceStatisticsOption<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, interface_id: Option<u32>, code: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            2 => InterfaceStatisticsOption::IsbStartTime(state.decode_timestamp::<B>(interface_id.unwrap(), &mut slice)?),
            3 => InterfaceStatisticsOption::IsbEndTime(state.decode_timestamp::<B>(interface_id.unwrap(), &mut slice)?),
            4 => InterfaceStatisticsOption::IsbIfRecv(slice.read_u64::<B>().map_err(|_| PcapError::IncompleteBuffer)?),
            5 => InterfaceStatisticsOption::IsbIfDrop(slice.read_u64::<B>().map_err(|_| PcapError::IncompleteBuffer)?),
            6 => InterfaceStatisticsOption::IsbFilterAccept(slice.read_u64::<B>().map_err(|_| PcapError::IncompleteBuffer)?),
            7 => InterfaceStatisticsOption::IsbOsDrop(slice.read_u64::<B>().map_err(|_| PcapError::IncompleteBuffer)?),
            8 => InterfaceStatisticsOption::IsbUsrDeliv(slice.read_u64::<B>().map_err(|_| PcapError::IncompleteBuffer)?),

            _ => InterfaceStatisticsOption::Common(CommonOption::new::<B>(code, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, interface_id: Option<u32>, writer: &mut W) -> Result<usize, PcapError> {
        Ok(match self {
            InterfaceStatisticsOption::IsbStartTime(a) => write_timestamp::<B, W>(2, a, state, interface_id, writer)?,
            InterfaceStatisticsOption::IsbEndTime(a) => write_timestamp::<B, W>(3, a, state, interface_id, writer)?,
            InterfaceStatisticsOption::IsbIfRecv(a) => a.write_opt_to::<B, W>(4, writer)?,
            InterfaceStatisticsOption::IsbIfDrop(a) => a.write_opt_to::<B, W>(5, writer)?,
            InterfaceStatisticsOption::IsbFilterAccept(a) => a.write_opt_to::<B, W>(6, writer)?,
            InterfaceStatisticsOption::IsbOsDrop(a) => a.write_opt_to::<B, W>(7, writer)?,
            InterfaceStatisticsOption::IsbUsrDeliv(a) => a.write_opt_to::<B, W>(8, writer)?,
            InterfaceStatisticsOption::Common(a) => a.write_opt_to::<B, W>(a.code(), writer)?,
        })
    }
}

/// Helper for writing options that contain timestamps.
fn write_timestamp<B: ByteOrder, W: Write>(
    code: u16,
    timestamp: &Duration,
    state: &PcapNgState,
    interface_id: Option<u32>,
    writer: &mut W
) -> Result<usize, PcapError> {
    const TIMESTAMP_LENGTH: u16 = 8;
    const OPTION_LENGTH: usize = 12;
    writer.write_u16::<B>(code)?;
    writer.write_u16::<B>(TIMESTAMP_LENGTH)?;
    state.encode_timestamp::<B, W>(interface_id.unwrap(), *timestamp, writer)?;
    Ok(OPTION_LENGTH)
}
