use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::interface_description::{InterfaceDescriptionBlock, TsResolution};
use super::blocks::section_header::SectionHeaderBlock;
use super::blocks::{INTERFACE_DESCRIPTION_BLOCK, SECTION_HEADER_BLOCK};
use crate::errors::PcapError;

#[cfg(doc)]
use {
    super::blocks::interface_description::InterfaceDescriptionOption,
    crate::pcapng::{PcapNgReader, PcapNgWriter},
    crate::Endianness,
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
    /// Timestamp resolutions and offsets corresponding to the interfaces
    pub(crate) ts_parameters: Vec<(TsResolution, Duration)>,
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
    pub fn update_from_block(&mut self, block: &Block) -> Result<(), PcapError> {
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
    pub fn update_from_raw_block<B: ByteOrder>(&mut self, raw_block: &RawBlock) -> Result<(), PcapError> {
        match raw_block.type_ {
            SECTION_HEADER_BLOCK | INTERFACE_DESCRIPTION_BLOCK => {
                let block = raw_block.clone().try_into_block::<B>(self)?;
                self.update_from_block(&block)
            },
            _ => Ok(())
        }
    }

    /// Decode a timestamp using the correct format for the current state.
    pub fn decode_timestamp<B: ByteOrder>(&self, interface_id: u32, slice: &mut &[u8]) -> Result<Duration, PcapError> {

        let timestamp_high = slice
            .read_u32::<B>()
            .map_err(|_| PcapError::IncompleteBuffer(4, slice.len()))? as u64;

        let timestamp_low = slice
            .read_u32::<B>()
            .map_err(|_| PcapError::IncompleteBuffer(4, slice.len()))? as u64;

        let ts_raw = (timestamp_high << 32) + timestamp_low;

        let (ts_resolution, ts_offset) = self
            .ts_parameters
            .get(interface_id as usize)
            .ok_or(PcapError::InvalidInterfaceId(interface_id))?;

        let ts_nanos = ts_raw * ts_resolution.to_nano_secs() as u64;

        Ok(Duration::from_nanos(ts_nanos) + *ts_offset)
    }

    /// Encode a timestamp using the correct format for the current state.
    pub fn encode_timestamp<B: ByteOrder, W: Write>(&self, interface_id: u32, timestamp: Duration, writer: &mut W) -> Result<(), PcapError> {

        let (ts_resolution, ts_offset) = self
            .ts_parameters
            .get(interface_id as usize)
            .ok_or(PcapError::InvalidInterfaceId(interface_id))?;

        let ts_relative = timestamp - *ts_offset;

        let ts_raw = ts_relative.as_nanos() / ts_resolution.to_nano_secs() as u128;

        let ts_raw: u64 = ts_raw
            .try_into()
            .or(Err(PcapError::TimestampTooBig))?;

        let timestamp_high = (ts_raw >> 32) as u32;
        let timestamp_low = (ts_raw & 0xFFFFFFFF) as u32;

        writer.write_u32::<B>(timestamp_high)?;
        writer.write_u32::<B>(timestamp_low)?;

        Ok(())
    }
}
