use derive_into_owned::IntoOwned;
use crate::pcapng::{Block, PcapNgBlock};
use std::borrow::Cow;
use byteorder::ByteOrder;
use std::io::Write;
use std::io::Result as IoResult;
use crate::PcapError;

#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownBlock<'a> {
    pub type_: u32,
    pub length: u32,
    pub value: Cow<'a, [u8]>
}

impl<'a> UnknownBlock<'a> {
    pub fn new(type_: u32, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock {
            type_,
            length,
            value: Cow::Borrowed(value)
        }
    }
}

impl<'a> PcapNgBlock<'a> for UnknownBlock<'a> {
    fn from_slice<B: ByteOrder>(_slice: &'a [u8]) -> Result<(&[u8], Self), PcapError> where Self: Sized {
        unimplemented!("UnkknownBlock::<as PcapNgBlock>::From_slice shouldn't be called")
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_all(&self.value)?;
        Ok(self.value.len() as usize)
    }

    fn into_block(self) -> Block<'a> {
        Block::Unknown(self)
    }
}