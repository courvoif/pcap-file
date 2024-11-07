use std::time::Duration;

use byteorder_slice::ByteOrder;

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
    /// Timestamp resolutions corresponding to the interfaces
    pub(crate) ts_resolutions: Vec<TsResolution>,
}

impl PcapNgState {
    /// Update the state based on the next [`Block`].
    pub fn update_from_block(&mut self, block: &Block) -> Result<(), PcapError> {
        match block {
            Block::SectionHeader(blk) => {
                self.section = blk.clone().into_owned();
                self.interfaces.clear();
                self.ts_resolutions.clear();
            },
            Block::InterfaceDescription(blk) => {
                let ts_resolution = blk.ts_resolution()?;
                self.ts_resolutions.push(ts_resolution);

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
                let block = raw_block.clone().try_into_block::<B>()?;
                self.update_from_block(&block)
            },
            _ => Ok(())
        }
    }

    /// Decode a timestamp using the correct format for the current state.
    pub(crate) fn decode_timestamp(&self, interface_id: u32, ts_raw: u64) -> Result<Duration, PcapError> {
        let ts_resolution = self
            .ts_resolutions
            .get(interface_id as usize)
            .ok_or(PcapError::InvalidInterfaceId(interface_id))?;

        let ts_nanos = ts_raw * ts_resolution.to_nano_secs() as u64;

        Ok(Duration::from_nanos(ts_nanos))
    }

    /// Encode a timestamp using the correct format for the current state.
    pub(crate) fn encode_timestamp(&self, interface_id: u32, timestamp: Duration) -> std::io::Result<u64> {
        let ts_resolution = self
            .ts_resolutions
            .get(interface_id as usize)
            .ok_or(std::io::Error::other("Invalid interface ID"))?;

        let ts_raw = timestamp.as_nanos() / ts_resolution.to_nano_secs() as u128;

        ts_raw
            .try_into()
            .map_err(|_| std::io::Error::other(
                "Timestamp too big, please use a bigger timestamp resolution"))
    }
}
