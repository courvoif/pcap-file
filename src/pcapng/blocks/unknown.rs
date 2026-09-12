//! Unknown Block.

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::ByteOrder;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use crate::pcapng::{
    PcapNgState,
    errors::{BlockContentParseError, PcapNgWriteError},
};

/// Unknown Block.
///
/// Stores a pcapng block whose type is not recognized.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownBlock<'a> {
    /// Numeric block type.
    pub type_: u32,
    /// Total block length.
    pub length: u32,
    /// Unparsed block body.
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownBlock<'a> {
    /// Creates a new [`UnknownBlock`].
    pub fn new(type_: u32, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock {
            type_,
            length,
            value: Cow::Borrowed(value),
        }
    }
}

impl<'a> PcapNgBlock<'a> for UnknownBlock<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockContentParseError>
    where
        Self: Sized,
    {
        unimplemented!("UnknownBlock::<as PcapNgBlock>::from_slice shouldn't be called")
    }

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError> {
        writer.write_all(&self.value)?;
        Ok(self.value.len())
    }

    fn into_block(self) -> Block<'a> {
        Block::Unknown(self)
    }
}
