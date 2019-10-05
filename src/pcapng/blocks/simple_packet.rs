use crate::errors::PcapError;
use crate::DataLink;
use std::io::Read;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::peek_reader::PeekReader;
use std::borrow::Cow;


/// The Simple Packet Block (SPB) is a lightweight container for storing the packets coming from the network.
/// Its presence is optional.
#[derive(Clone, Debug)]
pub struct SimplePacketBlock<'a> {

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: &'a [u8]
}

impl<'a> SimplePacketBlock<'a> {

    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(Self, &'a[u8]), PcapError> {

        if slice.len() < 4 {
            return Err(PcapError::IncompleteBuffer(4 - slice.len()));
        }
        let original_len = slice.read_u32::<B>()? as usize;

        if slice.len() < original_len {
            return Err(PcapError::IncompleteBuffer(original_len - slice.len()));
        }
        let packet = SimplePacketBlock {
            original_len: original_len as u32,
            data: &slice[..original_len]
        };

        Ok((packet, &slice[original_len..]))
    }
}
