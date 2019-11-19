use crate::errors::PcapError;
use byteorder::{ByteOrder, ReadBytesExt};
use std::borrow::Cow;
use derive_into_owned::IntoOwned;


/// The Simple Packet Block (SPB) is a lightweight container for storing the packets coming from the network.
/// Its presence is optional.
#[derive(Clone, Debug, IntoOwned)]
pub struct SimplePacketBlock<'a> {

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>
}

impl<'a> SimplePacketBlock<'a> {

    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {

        if slice.len() < 4 {
            return Err(PcapError::InvalidField("SimplePacketBlock: block length < 4"));
        }
        let original_len = slice.read_u32::<B>()?;

        let packet = SimplePacketBlock {
            original_len,
            data: Cow::Borrowed(slice)
        };

        Ok((&[], packet))
    }
}
