//! Custom Block.

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::{ReadBytesExt, WriteBytesExt};

use super::block_common::{Block, PcapNgBlock};
use crate::pcapng::PcapNgState;
use crate::PcapError;

/// Custom block
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomBlock<'a, const COPIABLE: bool> {
    /// Private Enterprise Number of the entity which defined this block.
    pub pen: u32,
    /// Payload of this block.
    pub payload: Cow<'a, [u8]>,
}

impl<'a> CustomBlock<'a, true> {
    /// Converts this block's payload into a type that implements [`CustomCopiable`].
    pub fn interpret<T: CustomCopiable<'a>>(&'a self) -> Result<Option<T>, PcapError> {
        if self.pen != T::PEN {
            return Ok(None)
        }

        T::from_slice(&self.payload)
    }
}

impl<'a> CustomBlock<'a, false> {
    /// Converts this block's payload into a type that implements [`CustomNonCopiable`].
    pub fn interpret<T: CustomNonCopiable<'a>>(&'a self, state: &T::State)
        -> Result<Option<T>, PcapError>
    {
        if self.pen != T::PEN {
            return Ok(None)
        }

        T::from_slice(state, &self.payload)
    }
}

impl<const COPIABLE: bool> CustomBlock<'_, COPIABLE> {
    // The into_owned method must be implemented manually,
    // since derive_into_owned can't handle the const generic.

    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomBlock<'static, COPIABLE> {
        CustomBlock {
            pen: self.pen,
            payload: Cow::Owned(self.payload.into_owned())
        }
    }
}

/// Common interface for copiable custom block payloads
pub trait CustomCopiable<'a> {
    /// Private Enterprise Number of the entity which defined this payload format.
    const PEN: u32;

    /// Try to parse this payload from a slice.
    fn from_slice(slice: &'a [u8]) -> Result<Option<Self>, PcapError>
        where Self: Sized;

    /// Write this payload into a writer.
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), PcapError>;

    /// Convert this block into a copiable [`CustomBlock`]
    fn into_custom_block(self) -> Result<CustomBlock<'a, true>, PcapError>
        where Self: Sized
    {
        let mut data = Vec::new();
        self.write_to(&mut data)?;

        Ok(CustomBlock { pen: Self::PEN, payload: Cow::Owned(data) })
    }
}

/// Common interface for non-copiable custom block payloads
pub trait CustomNonCopiable<'a> {
    /// Private Enterprise Number of the entity which defined this payload format.
    const PEN: u32;

    /// State that may be required to parse/write the block.
    type State;

    /// Try to parse this payload from a slice.
    fn from_slice(state: &Self::State, slice: &'a [u8]) -> Result<Option<Self>, PcapError>
        where Self: Sized;

    /// Write this payload into a writer.
    fn write_to<W: Write>(&self, state: &Self::State, writer: &mut W)
        -> Result<(), PcapError>;

    /// Convert this block into a non-copiable [`CustomBlock`]
    fn into_custom_block(self, state: &Self::State) -> Result<CustomBlock<'a, false>, PcapError>
        where Self: Sized
    {
        let mut data = Vec::new();
        self.write_to(state, &mut data)?;

        Ok(CustomBlock { pen: Self::PEN, payload: Cow::Owned(data) })
    }
}

impl<'a, const COPIABLE: bool> PcapNgBlock<'a> for CustomBlock<'a, COPIABLE> {
    fn from_slice<B: ByteOrder>(_state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError>
    where
        Self: Sized,
    {
        let pen = slice.read_u32::<B>()?;
        Ok((&[], CustomBlock { pen, payload: Cow::Borrowed(slice) }))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, _state: &PcapNgState, writer: &mut W) -> Result<usize, PcapError> {
        writer.write_u32::<B>(self.pen)?;
        writer.write_all(&self.payload)?;
        Ok(4 + self.payload.len())
    }

    fn into_block(self) -> Block<'a> {
        if COPIABLE {
            Block::CustomCopiable(CustomBlock { pen: self.pen, payload: self.payload })
        } else {
            Block::CustomNonCopiable(CustomBlock { pen: self.pen, payload: self.payload })
        }
    }
}
