use derive_into_owned::IntoOwned;
use crate::pcapng::{BlockType, ParsedBlock};
use std::borrow::Cow;
use byteorder::{ByteOrder, WriteBytesExt};
use std::io::Write;
use std::io::Result as IoResult;

#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownBlock<'a> {
    pub type_: BlockType,
    pub length: u32,
    pub value: Cow<'a, [u8]>
}

impl<'a> UnknownBlock<'a> {

    pub fn new(type_: BlockType, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock {
            type_,
            length,
            value: Cow::Borrowed(value)
        }
    }

    pub fn write_block_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        writer.write_u32::<B>( self.type_.into())?;
        writer.write_u32::<B>(self.length)?;
        writer.write_all(&self.value)?;
        writer.write_u32::<B>(self.length)?;

        Ok(self.length as usize)
    }

    pub fn into_parsed(self) -> ParsedBlock<'a> {
        ParsedBlock::Unknown(self)
    }
}