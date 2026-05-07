//! Interface Statistics Block.

use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CommonOption, PcapNgOption, WriteOptTo};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockContentParseError, OptionEntryError, PcapNgWriteError};

/// The Interface Statistics Block contains the capture statistics for a given interface and it is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct InterfaceStatisticsBlock<'a> {
    /// Specifies the interface these statistics refers to.
    ///
    /// The correct interface will be the one whose Interface Description Block (within the current Section of the file)
    /// is identified by same number of this field.
    pub interface_id: u32,

    /// Time this statistics refers to (Nanoseconds elapsed since 1970-01-01 00:00:00 UTC.)
    pub timestamp: i128,

    /// Options
    pub options: Vec<InterfaceStatisticsOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for InterfaceStatisticsBlock<'a> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), BlockContentParseError> {
        if slice.len() < 12 {
            return Err(BlockContentParseError::BlockContentTooSmall { needed: 12, actual: slice.len() });
        }

        let interface_id = slice.read_u32::<B>().unwrap();
        let timestamp_high = slice.read_u32::<B>().unwrap();
        let timestamp_low = slice.read_u32::<B>().unwrap();
        let timestamp = state.decode_timestamp(interface_id, timestamp_high, timestamp_low)?;
        let (slice, options) = InterfaceStatisticsOption::opts_from_slice::<B>(state, Some(interface_id), slice)?;

        let block = InterfaceStatisticsBlock { interface_id, timestamp, options };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        writer.write_u32::<B>(self.interface_id)?;
        let (timestamp_high, timestamp_low) = state
            .encode_timestamp(self.interface_id, self.timestamp)
            .map_err(|source| PcapNgWriteError::Validation { field: "InterfaceStatisticsBlock.timestamp", source })?;
        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;

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
    IsbStartTime(i128),

    /// The isb_endtime option specifies the time the capture ended.
    ///
    /// The time is relative to 1970-01-01 00:00:00 UTC.
    IsbEndTime(i128),

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

impl InterfaceStatisticsOption<'_> {
    const ISB_START_TIME: u16 = 2;
    const ISB_END_TIME: u16 = 3;
    const ISB_IF_RECV: u16 = 4;
    const ISB_IF_DROP: u16 = 5;
    const ISB_FILTER_ACCEPT: u16 = 6;
    const ISB_OS_DROP: u16 = 7;
    const ISB_USR_DELIV: u16 = 8;
}

impl<'a> PcapNgOption<'a> for InterfaceStatisticsOption<'a> {
    fn from_slice<B: ByteOrder>(
        state: &PcapNgState,
        interface_id: Option<u32>,
        code: u16,
        mut slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::ISB_START_TIME => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                let timestamp_high = slice.read_u32::<B>().unwrap();
                let timestamp_low = slice.read_u32::<B>().unwrap();
                InterfaceStatisticsOption::IsbStartTime(state.decode_timestamp(interface_id.unwrap(), timestamp_high, timestamp_low)?)
            },
            Self::ISB_END_TIME => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                let timestamp_high = slice.read_u32::<B>().unwrap();
                let timestamp_low = slice.read_u32::<B>().unwrap();
                InterfaceStatisticsOption::IsbEndTime(state.decode_timestamp(interface_id.unwrap(), timestamp_high, timestamp_low)?)
            },
            Self::ISB_IF_RECV => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceStatisticsOption::IsbIfRecv(slice.read_u64::<B>().unwrap())
            },
            Self::ISB_IF_DROP => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceStatisticsOption::IsbIfDrop(slice.read_u64::<B>().unwrap())
            },
            Self::ISB_FILTER_ACCEPT => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceStatisticsOption::IsbFilterAccept(slice.read_u64::<B>().unwrap())
            },
            Self::ISB_OS_DROP => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceStatisticsOption::IsbOsDrop(slice.read_u64::<B>().unwrap())
            },
            Self::ISB_USR_DELIV => {
                if slice.len() != 8 {
                    return Err(OptionEntryError::WrongSize { expected: 8, actual: slice.len() });
                }
                InterfaceStatisticsOption::IsbUsrDeliv(slice.read_u64::<B>().unwrap())
            },

            _ => InterfaceStatisticsOption::Common(CommonOption::new::<B>(code, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError> {
        match self {
            InterfaceStatisticsOption::IsbStartTime(a) => write_timestamp::<B, W>(Self::ISB_START_TIME, *a, state, interface_id, writer),
            InterfaceStatisticsOption::IsbEndTime(a) => write_timestamp::<B, W>(Self::ISB_END_TIME, *a, state, interface_id, writer),
            InterfaceStatisticsOption::IsbIfRecv(a) => a.write_opt_to::<B, W>(Self::ISB_IF_RECV, writer),
            InterfaceStatisticsOption::IsbIfDrop(a) => a.write_opt_to::<B, W>(Self::ISB_IF_DROP, writer),
            InterfaceStatisticsOption::IsbFilterAccept(a) => a.write_opt_to::<B, W>(Self::ISB_FILTER_ACCEPT, writer),
            InterfaceStatisticsOption::IsbOsDrop(a) => a.write_opt_to::<B, W>(Self::ISB_OS_DROP, writer),
            InterfaceStatisticsOption::IsbUsrDeliv(a) => a.write_opt_to::<B, W>(Self::ISB_USR_DELIV, writer),
            InterfaceStatisticsOption::Common(a) => a.write_opt_to::<B, W>(a.code(), writer),
        }
    }

    fn code_name(code: u16) -> &'static str {
        match code {
            Self::ISB_START_TIME => "IsbStartTime",
            Self::ISB_END_TIME => "IsbEndTime",
            Self::ISB_IF_RECV => "IsbIfRecv",
            Self::ISB_IF_DROP => "IsbIfDrop",
            Self::ISB_FILTER_ACCEPT => "IsbFilterAccept",
            Self::ISB_OS_DROP => "IsbOsDrop",
            Self::ISB_USR_DELIV => "IsbUsrDeliv",
            _ => CommonOption::code_name(code),
        }
    }
}

/// Helper for writing options that contain timestamps.
fn write_timestamp<B: ByteOrder, W: Write>(
    code: u16,
    timestamp: i128,
    state: &PcapNgState,
    interface_id: Option<u32>,
    writer: &mut W,
) -> Result<usize, PcapNgWriteError> {
    const TIMESTAMP_LENGTH: u16 = 8;
    const OPTION_LENGTH: usize = 12;
    writer.write_u16::<B>(code)?;
    writer.write_u16::<B>(TIMESTAMP_LENGTH)?;
    let (timestamp_high, timestamp_low) = state
        .encode_timestamp(interface_id.unwrap(), timestamp)
        .map_err(|source| PcapNgWriteError::Validation { field: "InterfaceStatisticsOption.timestamp", source })?;
    writer.write_u32::<B>(timestamp_high)?;
    writer.write_u32::<B>(timestamp_low)?;
    Ok(OPTION_LENGTH)
}
