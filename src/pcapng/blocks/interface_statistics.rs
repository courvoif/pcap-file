//! Interface Statistics Block.

/* ----- Imports ----- */

use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{
    CommonOption, PcapNgOption, RawOption, check_opt_len, opts_from_slice, validate_opts, validate_unique_opts,
    write_opts_to, write_u64_option,
};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, OptionEntryError, WriteError};

/* ----- InterfaceStatisticsBlock ----- */

/// The Interface Statistics Block contains the capture statistics for a given interface and it is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct InterfaceStatisticsBlock<'a> {
    /// Specifies the interface these statistics refers to.
    ///
    /// The correct interface will be the one whose Interface Description Block (within the current Section of the file)
    /// is identified by same number of this field.
    pub interface_id: u32,

    /// Time elapsed since 1970-01-01 00:00:00 UTC to which these statistics refer.
    pub timestamp: Duration,

    /// Options
    pub options: Vec<InterfaceStatisticsOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for InterfaceStatisticsBlock<'a> {
    const TYPE: u32 = 0x00000005;
    const NAME: &'static str = "Interface Statistics Block";

    fn validate(&self, state: &PcapNgState) -> Result<(), BlockValidationError> {
        state
            .interfaces
            .get(self.interface_id as usize)
            .ok_or(BlockValidationError::InvalidInterfaceId(self.interface_id))?;

        validate_unique_opts(&self.options, |option| {
            !matches!(option, InterfaceStatisticsOption::Common(_))
        })
        .map_err(BlockValidationError::Option)?;

        validate_opts(&self.options, state, Some(self.interface_id)).map_err(BlockValidationError::Option)
    }

    fn from_body<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError> {
        if slice.len() < 12 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 12,
                actual: slice.len(),
            });
        }

        let interface_id = slice.read_u32::<B>().unwrap();
        let timestamp_high = slice.read_u32::<B>().unwrap();
        let timestamp_low = slice.read_u32::<B>().unwrap();
        let timestamp = state.decode_timestamp(interface_id, timestamp_high, timestamp_low)?;
        let (slice, options) = opts_from_slice::<B, InterfaceStatisticsOption>(state, Some(interface_id), slice)?;

        let block = InterfaceStatisticsBlock {
            interface_id,
            timestamp,
            options,
        };

        Ok((slice, block))
    }

    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        let (timestamp_high, timestamp_low) = state
            .encode_timestamp(self.interface_id, self.timestamp)
            .map_err(|error| WriteError::Other(BlockValidationError::Timestamp(error)))?;

        writer.write_u32::<B>(self.interface_id)?;
        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;

        let opt_len = write_opts_to::<B, _, _>(&self.options, state, Some(self.interface_id), writer)
            .map_err(|error| error.map_other(BlockValidationError::Option))?;

        Ok(12 + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::InterfaceStatistics(self)
    }
}

/* ----- InterfaceStatisticsOption ----- */

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
    fn from_content<B: ByteOrder>(
        state: &PcapNgState,
        interface_id: Option<u32>,
        code: u16,
        mut slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        let opt = match code {
            Self::ISB_START_TIME => {
                check_opt_len(slice, 8)?;
                let interface_id = interface_id.ok_or(OptionEntryError::MissingInterfaceId)?;

                let timestamp_high = slice.read_u32::<B>().expect("option length checked above");
                let timestamp_low = slice.read_u32::<B>().expect("option length checked above");

                InterfaceStatisticsOption::IsbStartTime(state.decode_timestamp(
                    interface_id,
                    timestamp_high,
                    timestamp_low,
                )?)
            }
            Self::ISB_END_TIME => {
                check_opt_len(slice, 8)?;
                let interface_id = interface_id.ok_or(OptionEntryError::MissingInterfaceId)?;

                let timestamp_high = slice.read_u32::<B>().expect("option length checked above");
                let timestamp_low = slice.read_u32::<B>().expect("option length checked above");

                InterfaceStatisticsOption::IsbEndTime(state.decode_timestamp(
                    interface_id,
                    timestamp_high,
                    timestamp_low,
                )?)
            }
            Self::ISB_IF_RECV => {
                check_opt_len(slice, 8)?;
                InterfaceStatisticsOption::IsbIfRecv(slice.read_u64::<B>().unwrap())
            }
            Self::ISB_IF_DROP => {
                check_opt_len(slice, 8)?;
                InterfaceStatisticsOption::IsbIfDrop(slice.read_u64::<B>().unwrap())
            }
            Self::ISB_FILTER_ACCEPT => {
                check_opt_len(slice, 8)?;
                InterfaceStatisticsOption::IsbFilterAccept(slice.read_u64::<B>().unwrap())
            }
            Self::ISB_OS_DROP => {
                check_opt_len(slice, 8)?;
                InterfaceStatisticsOption::IsbOsDrop(slice.read_u64::<B>().unwrap())
            }
            Self::ISB_USR_DELIV => {
                check_opt_len(slice, 8)?;
                InterfaceStatisticsOption::IsbUsrDeliv(slice.read_u64::<B>().unwrap())
            }

            _ => InterfaceStatisticsOption::Common(CommonOption::from_content::<B>(code, slice)?),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        match self {
            InterfaceStatisticsOption::IsbStartTime(a) => {
                write_timestamp::<B, W>(Self::ISB_START_TIME, *a, state, interface_id, writer)
            }
            InterfaceStatisticsOption::IsbEndTime(a) => {
                write_timestamp::<B, W>(Self::ISB_END_TIME, *a, state, interface_id, writer)
            }
            InterfaceStatisticsOption::IsbIfRecv(a) => write_u64_option::<B, W>(writer, Self::ISB_IF_RECV, *a),
            InterfaceStatisticsOption::IsbIfDrop(a) => write_u64_option::<B, W>(writer, Self::ISB_IF_DROP, *a),
            InterfaceStatisticsOption::IsbFilterAccept(a) => {
                write_u64_option::<B, W>(writer, Self::ISB_FILTER_ACCEPT, *a)
            }
            InterfaceStatisticsOption::IsbOsDrop(a) => write_u64_option::<B, W>(writer, Self::ISB_OS_DROP, *a),
            InterfaceStatisticsOption::IsbUsrDeliv(a) => write_u64_option::<B, W>(writer, Self::ISB_USR_DELIV, *a),
            InterfaceStatisticsOption::Common(a) => a.write_to::<B, W>(writer),
        }
    }

    fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError> {
        Ok(())
    }

    fn code(&self) -> u16 {
        match self {
            Self::IsbStartTime(_) => Self::ISB_START_TIME,
            Self::IsbEndTime(_) => Self::ISB_END_TIME,
            Self::IsbIfRecv(_) => Self::ISB_IF_RECV,
            Self::IsbIfDrop(_) => Self::ISB_IF_DROP,
            Self::IsbFilterAccept(_) => Self::ISB_FILTER_ACCEPT,
            Self::IsbOsDrop(_) => Self::ISB_OS_DROP,
            Self::IsbUsrDeliv(_) => Self::ISB_USR_DELIV,
            Self::Common(option) => option.code(),
        }
    }

    fn name(code: u16) -> &'static str {
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

/* ----- Timestamp option encoding ----- */

/// Writes a timestamp option using the supplied interface's parameters.
///
/// # Errors
///
/// Supply an interface ID whose timestamp parameters can encode the value.
fn write_timestamp<B: ByteOrder, W: Write>(
    code: u16,
    timestamp: Duration,
    state: &PcapNgState,
    interface_id: Option<u32>,
    writer: &mut W,
) -> Result<usize, WriteError<OptionEntryError>> {
    let interface_id = interface_id.ok_or(WriteError::Other(OptionEntryError::MissingInterfaceId))?;
    let (timestamp_high, timestamp_low) = state
        .encode_timestamp(interface_id, timestamp)
        .map_err(|error| WriteError::Other(OptionEntryError::Timestamp(error)))?;

    RawOption::write_framed_to::<B, _, _>(writer, code, 8, |writer| {
        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;
        Ok(())
    })
}

/* ----- Tests ----- */

/// Checks that timestamp options report missing interface context.
#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use std::time::Duration;

    use byteorder_slice::BigEndian;

    use super::InterfaceStatisticsOption;
    use crate::pcapng::PcapNgState;
    use crate::pcapng::blocks::opt_common::{PcapNgOption, write_opts_to};
    use crate::pcapng::errors::{OptionEntryError, OptionError, WriteError};

    /* ----- Missing interface ID ----- */

    /// Rejects missing interface IDs when parsing or directly writing timestamp options.
    #[test]
    fn timestamp_options_require_interface_id() {
        let state = PcapNgState::default();

        for option in [
            InterfaceStatisticsOption::IsbStartTime(Duration::ZERO),
            InterfaceStatisticsOption::IsbEndTime(Duration::ZERO),
        ] {
            let error =
                InterfaceStatisticsOption::from_content::<BigEndian>(&state, None, option.code(), &[0; 8]).unwrap_err();
            assert!(matches!(error, OptionEntryError::MissingInterfaceId));

            let mut encoded = Vec::new();
            let error = option.write_to::<BigEndian, _>(&state, None, &mut encoded).unwrap_err();
            assert!(matches!(error, WriteError::Other(OptionEntryError::MissingInterfaceId)));
            assert!(encoded.is_empty());
        }
    }

    /// Reports the timestamp option's code when its interface context is missing.
    #[test]
    fn missing_interface_id_reports_option_error() {
        let state = PcapNgState::default();

        for timestamp in [
            InterfaceStatisticsOption::IsbStartTime(Duration::ZERO),
            InterfaceStatisticsOption::IsbEndTime(Duration::ZERO),
        ] {
            let code = timestamp.code();
            let options = [InterfaceStatisticsOption::IsbIfRecv(1), timestamp];
            let mut encoded = vec![42];
            let error = write_opts_to::<BigEndian, _, _>(&options, &state, None, &mut encoded).unwrap_err();

            assert!(matches!(
                error,
                WriteError::Other(OptionError { code: error_code, source, .. })
                    if error_code == code && matches!(*source, OptionEntryError::MissingInterfaceId)
            ));
        }
    }
}
