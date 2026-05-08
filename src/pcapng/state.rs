use byteorder_slice::ByteOrder;

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::interface_description::{InterfaceDescriptionBlock, TsResolution};
use super::blocks::section_header::SectionHeaderBlock;
use super::blocks::{INTERFACE_DESCRIPTION_BLOCK, SECTION_HEADER_BLOCK};
use crate::pcapng::errors::{ContentValidationError, StateUpdateError};

#[cfg(doc)]
use {
    super::blocks::interface_description::InterfaceDescriptionOption,
    crate::Endianness,
    crate::pcapng::{PcapNgReader, PcapNgWriter},
};

/// State that must be maintained whilst reading or writing a PcapNg stream.
///
/// This state is necessary because the encoding of blocks depends on
/// information seen earlier in the stream, such as the [`Endianness`] of the
/// [`SectionHeaderBlock`] and the [`TsResolution`] of each
/// [`InterfaceDescriptionBlock`].
///
/// Normally this state is maintained internally by a [`PcapNgReader`] or
/// [`PcapNgWriter`], but it's also possible to create a new [`PcapNgState`]
/// with [`PcapNgState::default`], and then update it by calling
/// [`PcapNgState::update_from_block`] or [`PcapNgState::update_from_raw_block`].
///
#[derive(Debug, Default)]
pub struct PcapNgState {
    /// Current section of the pcapng
    pub(crate) section: SectionHeaderBlock<'static>,
    /// List of the interfaces of the current section of the pcapng
    pub(crate) interfaces: Vec<InterfaceDescriptionBlock<'static>>,
    /// Timestamp resolutions and offsets (in seconds) corresponding to the interfaces
    pub(crate) ts_parameters: Vec<(TsResolution, i64)>,
}

impl PcapNgState {
    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.section
    }

    /// Returns all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.interfaces[..]
    }

    /// Update the state based on the next [`Block`].
    pub fn update_from_block(&mut self, block: &Block) -> Result<(), StateUpdateError> {
        match block {
            Block::SectionHeader(blk) => {
                self.section = blk.clone().into_owned();
                self.interfaces.clear();
                self.ts_parameters.clear();
            },
            Block::InterfaceDescription(blk) => {
                let ts_resolution = blk.ts_resolution()?;
                let ts_offset = blk.ts_offset();
                self.ts_parameters.push((ts_resolution, ts_offset));
                self.interfaces.push(blk.clone().into_owned());
            },
            _ => {},
        }
        Ok(())
    }

    /// Update the state based on the next [`RawBlock`].
    pub fn update_from_raw_block<B: ByteOrder>(&mut self, raw_block: &RawBlock) -> Result<(), StateUpdateError> {
        match raw_block.type_ {
            SECTION_HEADER_BLOCK | INTERFACE_DESCRIPTION_BLOCK => {
                let block = raw_block.clone().try_into_block_with_byteorder::<B>(self)?;

                self.update_from_block(&block)?;
                Ok(())
            },
            _ => Ok(()),
        }
    }

    /// Decode a timestamp using the correct format for the current state.
    pub fn decode_timestamp(&self, interface_id: u32, timestamp_high: u32, timestamp_low: u32) -> Result<i128, ContentValidationError> {
        let ts_raw = ((timestamp_high as u64) << 32) | timestamp_low as u64;

        let (ts_resolution, ts_offset) = self
            .ts_parameters
            .get(interface_id as usize)
            .ok_or(ContentValidationError::InvalidInterfaceId(interface_id))?;

        let ts_nanos = ts_resolution.decode_timestamp(ts_raw) + (*ts_offset as i128 * 1_000_000_000);

        Ok(ts_nanos)
    }

    /// Encode a timestamp using the correct format for the current state.
    pub fn encode_timestamp(&self, interface_id: u32, timestamp: i128) -> Result<(u32, u32), ContentValidationError> {
        let (ts_resolution, ts_offset) = self
            .ts_parameters
            .get(interface_id as usize)
            .ok_or(ContentValidationError::InvalidInterfaceId(interface_id))?;

        let offset_ns = (*ts_offset as i128) * 1_000_000_000;

        let ts_relative =
            timestamp
                .checked_sub(offset_ns)
                .ok_or(ContentValidationError::InvalidTimestamp(timestamp, *ts_resolution, *ts_offset))?;

        let ts_raw = ts_resolution
            .encode_timestamp(ts_relative)
            .map_err(|_| ContentValidationError::InvalidTimestamp(timestamp, *ts_resolution, *ts_offset))?;

        let timestamp_high = (ts_raw >> 32) as u32;
        let timestamp_low = (ts_raw & 0xFFFFFFFF) as u32;

        Ok((timestamp_high, timestamp_low))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_roundtrip_supports_dates_before_unix_epoch() {
        let mut state = PcapNgState::default();
        state.ts_parameters.push((TsResolution::SEC, -2));

        let timestamp = -1_000_000_000_i128;

        let (timestamp_high, timestamp_low) = state.encode_timestamp(0, timestamp).unwrap();
        let decoded = state.decode_timestamp(0, timestamp_high, timestamp_low).unwrap();

        assert_eq!(decoded, timestamp);
        assert_eq!((timestamp_high, timestamp_low), (0, 1));
    }

    #[test]
    fn encode_timestamp_rejects_offset_arithmetic_overflow() {
        let mut state = PcapNgState::default();
        state.ts_parameters.push((TsResolution::NANO, 1));

        let error = state.encode_timestamp(0, i128::MIN).unwrap_err();

        assert!(matches!(
            error,
            ContentValidationError::InvalidTimestamp(timestamp, resolution, offset)
                if timestamp == i128::MIN && resolution == TsResolution::NANO && offset == 1
        ));
    }

    #[test]
    fn encode_timestamp_truncates_sub_resolution_negative_value_to_zero() {
        let mut state = PcapNgState::default();
        state.ts_parameters.push((TsResolution::SEC, 0));

        let (timestamp_high, timestamp_low) = state.encode_timestamp(0, -1).unwrap();
        let decoded = state.decode_timestamp(0, timestamp_high, timestamp_low).unwrap();

        assert_eq!((timestamp_high, timestamp_low), (0, 0));
        assert_eq!(decoded, 0);
    }
}
