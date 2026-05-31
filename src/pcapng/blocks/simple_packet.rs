//! Simple Packet Block (SPB).

use std::borrow::Cow;
use std::cmp::min;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use crate::pcapng::errors::{BlockContentParseError, PcapNgWriteError};
use crate::pcapng::{ContentValidationError, PcapNgState};

/// The Simple Packet Block (SPB) is a lightweight container for storing the packets coming from the network.
///
/// Its presence is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SimplePacketBlock<'a> {
    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,
}

impl<'a> PcapNgBlock<'a> for SimplePacketBlock<'a> {
    fn from_slice<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockContentParseError> {
        if slice.len() < 4 {
            return Err(BlockContentParseError::BlockContentTooSmall {
                needed: 4,
                actual: slice.len(),
            });
        }

        // The interface of a simple packet is always the first interface of the section
        let Some(interface) = state.interfaces.first() else {
            return Err(ContentValidationError::NoInterface.into());
        };

        let original_len = slice.read_u32::<B>().unwrap();

        // Since the packet can be truncated, it's length is the minimum between snaplen (max captured length) and original_len (length on the wire).
        // If snaplen is 0 then there was no limit.
        let pkt_len = if interface.snaplen == 0 {
            original_len as usize
        } else {
            min(original_len, interface.snaplen) as usize
        };

        let pad_len = (4 - (pkt_len % 4)) % 4;
        let tot_len = pkt_len + pad_len;

        if slice.len() < tot_len {
            return Err(BlockContentParseError::BlockContentTooSmall {
                needed: tot_len,
                actual: slice.len(),
            });
        }

        let data = slice.read_slice(pkt_len).expect("slice length checked above");
        slice.move_forward(pad_len).expect("slice length checked above");

        let packet = SimplePacketBlock {
            original_len,
            data: Cow::Borrowed(data),
        };

        Ok((slice, packet))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapNgWriteError> {
        // Check that original_len is always >= self.data.len()
        if (self.original_len as usize) < self.data.len() {
            return Err(PcapNgWriteError::Validation {
                field: "SimplePacketBlock.original_len",
                source: ContentValidationError::InvalidOriginalLen(self.original_len, self.data.len()),
            });
        }

        // Check that original_length and data_len take snaplen into account //
        let Some(interface) = state.interfaces.first() else {
            return Err(PcapNgWriteError::Validation {
                field: "SimplePacketBlock.interface",
                source: ContentValidationError::NoInterface,
            });
        };

        let expected_len = if interface.snaplen == 0 {
            self.original_len as usize
        } else {
            min(self.original_len, interface.snaplen) as usize
        };

        if self.data.len() != expected_len {
            return Err(PcapNgWriteError::Validation {
                field: "SimplePacketBlock.data",
                source: ContentValidationError::InvalidCapturedLen {
                    expected: expected_len,
                    actual: self.data.len(),
                },
            });
        }

        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;

        let pad_len = (4 - (self.data.len() % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(4 + self.data.len() + pad_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::SimplePacket(self)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use byteorder_slice::BigEndian;

    use super::SimplePacketBlock;
    use crate::DataLink;
    use crate::pcapng::blocks::PcapNgBlock;
    use crate::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    use crate::pcapng::errors::{BlockContentParseError, PcapNgWriteError};
    use crate::pcapng::{ContentValidationError, PcapNgState};

    fn state_with_snaplen(snaplen: u32) -> PcapNgState {
        let mut state = PcapNgState::default();
        state.update_from_block(&InterfaceDescriptionBlock::new(DataLink::ETHERNET, snaplen).into_block());
        state
    }

    #[test]
    fn parse_rejects_simple_packet_without_interface() {
        let data = [0, 0, 0, 4, 0, 1, 2, 3];
        let err = SimplePacketBlock::from_slice::<BigEndian>(&PcapNgState::default(), &data).unwrap_err();

        assert!(matches!(
            err,
            BlockContentParseError::Validation(ContentValidationError::NoInterface)
        ));
    }

    #[test]
    fn parse_truncates_simple_packet_to_snaplen_and_consumes_padding() {
        let state = state_with_snaplen(2);
        let data = [
            0, 0, 0, 4, // original_len
            0, 1, // captured packet data
            0, 0, // padding
        ];

        let (rem, packet) = SimplePacketBlock::from_slice::<BigEndian>(&state, &data).unwrap();

        assert_eq!(packet.original_len, 4);
        assert_eq!(&packet.data[..], &[0, 1]);
        assert!(rem.is_empty());
    }

    #[test]
    fn write_rejects_simple_packet_without_interface() {
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1, 2, 3]),
        };
        let err = packet
            .write_to::<BigEndian, _>(&PcapNgState::default(), &mut Vec::new())
            .unwrap_err();

        assert!(matches!(
            err,
            PcapNgWriteError::Validation {
                field: "SimplePacketBlock.interface",
                source: ContentValidationError::NoInterface,
            }
        ));
    }

    #[test]
    fn write_rejects_simple_packet_shorter_than_expected_with_unlimited_snaplen() {
        let state = state_with_snaplen(0);
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1]),
        };
        let err = packet.write_to::<BigEndian, _>(&state, &mut Vec::new()).unwrap_err();

        assert!(matches!(
            err,
            PcapNgWriteError::Validation {
                field: "SimplePacketBlock.data",
                source: ContentValidationError::InvalidCapturedLen { expected: 4, actual: 2 },
            }
        ));
    }

    #[test]
    fn write_accepts_simple_packet_truncated_to_snaplen() {
        let state = state_with_snaplen(2);
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1]),
        };

        assert_eq!(packet.write_to::<BigEndian, _>(&state, &mut Vec::new()).unwrap(), 8);
    }

    #[test]
    fn write_rejects_simple_packet_longer_than_snaplen() {
        let state = state_with_snaplen(2);
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1, 2]),
        };
        let err = packet.write_to::<BigEndian, _>(&state, &mut Vec::new()).unwrap_err();

        assert!(matches!(
            err,
            PcapNgWriteError::Validation {
                field: "SimplePacketBlock.data",
                source: ContentValidationError::InvalidCapturedLen { expected: 2, actual: 3 },
            }
        ));
    }
}
