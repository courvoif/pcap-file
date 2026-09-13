//! State used while processing pcapng streams.

use std::time::Duration;

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::interface_description::{InterfaceDescriptionBlock, InterfaceTsResolution};
use super::blocks::section_header::SectionHeaderBlock;
use super::blocks::{INTERFACE_DESCRIPTION_BLOCK, SECTION_HEADER_BLOCK};
use crate::Endianness;
use crate::pcapng::errors::{ContentValidationError, StateUpdateError};

/// State maintained while reading or writing a pcapng stream.
///
/// This state is necessary because the encoding of blocks depends on
/// information seen earlier in the stream, such as the [`Endianness`] of the
/// [`SectionHeaderBlock`] and the [`InterfaceTsResolution`] of each
/// [`InterfaceDescriptionBlock`].
///
/// Normally, a [`PcapNgParser`], [`PcapNgReader`], or [`PcapNgWriter`]
/// maintains this state internally. It can also be created with
/// [`PcapNgState::default`] and updated with
/// [`PcapNgState::update_from_block`]. For raw blocks, call
/// [`PcapNgState::decode_block_if_needed`] first, then update the state if a
/// decoded block is returned.
///
/// [`PcapNgParser`]: crate::pcapng::PcapNgParser
/// [`PcapNgReader`]: crate::pcapng::PcapNgReader
/// [`PcapNgWriter`]: crate::pcapng::PcapNgWriter
#[derive(Debug, Default)]
pub struct PcapNgState {
    /// Current section of the pcapng stream.
    pub(crate) section: SectionHeaderBlock<'static>,
    /// Interfaces defined in the current section.
    pub(crate) interfaces: Vec<InterfaceDescriptionBlock<'static>>,
    /// Timestamp resolutions and offsets, in seconds, for the interfaces.
    pub(crate) ts_parameters: Vec<(InterfaceTsResolution, i64)>,
}

impl PcapNgState {
    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.section
    }

    /// Returns the current [`InterfaceDescriptionBlock`] values.
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.interfaces[..]
    }

    /// Returns the [`InterfaceDescriptionBlock`] identified by `interface_id`.
    pub fn interface(&self, interface_id: u32) -> Option<&InterfaceDescriptionBlock<'static>> {
        self.interfaces.get(interface_id as usize)
    }

    /// Returns the endianness of the current section.
    pub fn endianness(&self) -> Endianness {
        self.section.endianness
    }

    /// Decodes a [`RawBlock`] if it can change the state.
    ///
    /// Returns [`None`] unless the raw block is a Section Header or Interface
    /// Description block.
    ///
    /// # Errors
    ///
    /// - Returns [`StateUpdateError`] if a Section Header or Interface
    ///   Description block cannot be decoded or validated.
    pub fn decode_block_if_needed<'a>(&self, raw_block: &RawBlock<'a>) -> Result<Option<Block<'a>>, StateUpdateError> {
        match raw_block.type_ {
            SECTION_HEADER_BLOCK | INTERFACE_DESCRIPTION_BLOCK => {
                let block = raw_block
                    .clone()
                    .try_into_block(self)
                    .map_err(|error| StateUpdateError::BlockConversion(error.into()))?;
                Ok(Some(block))
            }
            _ => Ok(None),
        }
    }

    /// Updates the state from a Section Header or Interface Description block.
    /// Other block variants leave the state unchanged.
    pub fn update_from_block(&mut self, block: &Block) {
        match block {
            Block::SectionHeader(blk) => {
                self.section = blk.clone().into_owned();
                self.interfaces.clear();
                self.ts_parameters.clear();
            }
            Block::InterfaceDescription(blk) => {
                let ts_resolution = blk.ts_resolution();
                let ts_offset = blk.ts_offset();
                self.ts_parameters.push((ts_resolution, ts_offset));
                self.interfaces.push(blk.clone().into_owned());
            }
            _ => {}
        }
    }

    /// Returns the endianness to use when writing the given [`Block`].
    ///
    /// Takes an optional block as an argument to be used in conjunction with [`Self::decode_block_if_needed`].
    pub fn block_endianness(&self, block: Option<&Block>) -> Endianness {
        match block {
            Some(Block::SectionHeader(block)) => block.endianness,
            _ => self.endianness(),
        }
    }

    /// Decodes a timestamp using the referenced interface's resolution and offset.
    ///
    /// Returns the time elapsed since the Unix epoch.
    ///
    /// # Errors
    ///
    /// - Returns an error if `interface_id` does not identify an interface in
    ///   the current section.
    /// - Returns an error if applying the interface's timestamp resolution and
    ///   offset cannot produce a [`Duration`].
    pub fn decode_timestamp(
        &self,
        interface_id: u32,
        timestamp_high: u32,
        timestamp_low: u32,
    ) -> Result<Duration, ContentValidationError> {
        let ts_raw = ((timestamp_high as u64) << 32) | timestamp_low as u64;

        let (ts_resolution, ts_offset) = self
            .ts_parameters
            .get(interface_id as usize)
            .ok_or(ContentValidationError::InvalidInterfaceId(interface_id))?;

        let timestamp = ts_resolution.decode_timestamp(ts_raw);
        let offset = Duration::from_secs(ts_offset.unsigned_abs());

        if *ts_offset >= 0 {
            timestamp.checked_add(offset)
        } else {
            timestamp.checked_sub(offset)
        }
        .ok_or_else(|| ContentValidationError::FailedToDecodeTimestamp {
            timestamp_high,
            timestamp_low,
            resolution: *ts_resolution,
            offset: *ts_offset,
        })
    }

    /// Encodes a timestamp using the referenced interface's resolution and offset.
    ///
    /// `timestamp` is the time elapsed since the Unix epoch.
    ///
    /// # Errors
    ///
    /// - Returns an error if `interface_id` does not identify an interface in
    ///   the current section.
    /// - Returns an error if the timestamp cannot be represented using the
    ///   interface's resolution and offset.
    pub fn encode_timestamp(
        &self,
        interface_id: u32,
        timestamp: Duration,
    ) -> Result<(u32, u32), ContentValidationError> {
        let (ts_resolution, ts_offset) = self
            .ts_parameters
            .get(interface_id as usize)
            .ok_or(ContentValidationError::InvalidInterfaceId(interface_id))?;

        let offset = Duration::from_secs(ts_offset.unsigned_abs());
        let ts_relative = if *ts_offset >= 0 {
            timestamp.checked_sub(offset)
        } else {
            timestamp.checked_add(offset)
        }
        .ok_or(ContentValidationError::FailedToEncodeTimestamp {
            timestamp,
            resolution: *ts_resolution,
            offset: *ts_offset,
        })?;

        let ts_raw = ts_resolution.encode_timestamp(ts_relative).map_err(|_| {
            ContentValidationError::FailedToEncodeTimestamp {
                timestamp,
                resolution: *ts_resolution,
                offset: *ts_offset,
            }
        })?;

        let timestamp_high = (ts_raw >> 32) as u32;
        let timestamp_low = (ts_raw & 0xFFFFFFFF) as u32;

        Ok((timestamp_high, timestamp_low))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_timestamp_rejects_dates_before_unix_epoch() {
        let mut state = PcapNgState::default();
        state.ts_parameters.push((InterfaceTsResolution::SEC, -2));

        let error = state.decode_timestamp(0, 0, 1).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("high: 0x0"));
        assert!(message.contains("low: 0x1"));
        assert!(message.contains("combined: 1"));

        assert!(matches!(
            error,
            ContentValidationError::FailedToDecodeTimestamp {
                timestamp_high,
                timestamp_low,
                resolution,
                offset,
            } if timestamp_high == 0
                    && timestamp_low == 1
                    && resolution == InterfaceTsResolution::SEC
                    && offset == -2
        ));
    }

    #[test]
    fn encode_timestamp_rejects_timestamp_before_interface_offset() {
        let mut state = PcapNgState::default();
        state.ts_parameters.push((InterfaceTsResolution::SEC, 1));

        let timestamp = Duration::from_millis(999);
        let error = state.encode_timestamp(0, timestamp).unwrap_err();

        assert!(matches!(
            error,
            ContentValidationError::FailedToEncodeTimestamp {
                timestamp,
                resolution,
                offset,
            } if timestamp == Duration::from_millis(999)
                    && resolution == InterfaceTsResolution::SEC
                    && offset == 1
        ));
    }

    #[test]
    fn encode_timestamp_rejects_binary_resolution_arithmetic_overflow() {
        let mut state = PcapNgState::default();
        state
            .ts_parameters
            .push((InterfaceTsResolution::new(true, 29).unwrap(), 0));

        let error = state.encode_timestamp(0, Duration::MAX).unwrap_err();

        assert!(matches!(
            error,
            ContentValidationError::FailedToEncodeTimestamp {
                timestamp,
                resolution,
                offset,
            } if timestamp == Duration::MAX
                    && resolution == InterfaceTsResolution::new(true, 29).unwrap()
                    && offset == 0
        ));
    }

    #[test]
    fn timestamp_roundtrip_uses_duration() {
        let mut state = PcapNgState::default();
        state.ts_parameters.push((InterfaceTsResolution::SEC, 0));

        let (timestamp_high, timestamp_low) = state.encode_timestamp(0, Duration::from_nanos(1)).unwrap();
        let decoded = state.decode_timestamp(0, timestamp_high, timestamp_low).unwrap();

        assert_eq!((timestamp_high, timestamp_low), (0, 0));
        assert_eq!(decoded, Duration::ZERO);
    }
}
