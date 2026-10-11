//! [`Simple Packet Block`](SimplePacketBlock).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::cmp::min;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, WriteError};

/* ----- Simple packets ----- */

/// The Simple Packet Block (SPB) is a lightweight container for storing the packets coming from the network.
///
/// Uses interface zero in the current section and has no timestamp.
/// Captured data must have length `min(original_len, snaplen)`, or `original_len` when snaplen is zero.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SimplePacketBlock<'a> {
    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,
}

impl<'a> PcapNgBlock<'a> for SimplePacketBlock<'a> {
    /// Numeric type code of this block.
    const TYPE: u32 = 0x00000003;
    /// Human-readable name of this block.
    const NAME: &'static str = "Simple Packet Block";
    /// Decodes this block body using the supplied section state.
    fn from_body<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError> {
        if slice.len() < 4 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 4,
                actual: slice.len(),
            });
        }

        // The interface of a simple packet is always the first interface of the section
        let Some(interface) = state.interfaces.first() else {
            return Err(BlockValidationError::NoInterface);
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
            return Err(BlockValidationError::ContentTooSmall {
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

    /// Checks the constraints applicable to this value.
    fn validate(&self, state: &PcapNgState) -> Result<(), BlockValidationError> {
        if (self.original_len as usize) < self.data.len() {
            return Err(BlockValidationError::InvalidOriginalLen(
                self.original_len,
                self.data.len(),
            ));
        }

        let interface = state.interfaces.first().ok_or(BlockValidationError::NoInterface)?;

        let expected_len = if interface.snaplen == 0 {
            self.original_len as usize
        } else {
            min(self.original_len, interface.snaplen) as usize
        };

        if self.data.len() != expected_len {
            return Err(BlockValidationError::InvalidCapturedLen {
                expected: expected_len,
                actual: self.data.len(),
            });
        }

        Ok(())
    }

    /// Writes this block body using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;

        let pad_len = (4 - (self.data.len() % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(4 + self.data.len() + pad_len)
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::SimplePacket(self)
    }
}

/* ----- Tests ----- */

/// Checks this module's capture behavior.
#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use std::borrow::Cow;

    use byteorder_slice::BigEndian;

    use super::SimplePacketBlock;
    use crate::DataLink;
    use crate::pcapng::PcapNgState;
    use crate::pcapng::blocks::PcapNgBlock;
    use crate::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    use crate::pcapng::errors::BlockValidationError;

    /* ----- Test state ----- */

    /// Builds interface state with the requested capture limit.
    fn state_with_snaplen(snaplen: u32) -> PcapNgState {
        let mut state = PcapNgState::default();
        state.update_from_block(&InterfaceDescriptionBlock::new(DataLink::ETHERNET, snaplen).into_block());
        state
    }

    /* ----- Packet validation and encoding ----- */

    /// Checks that Simple Packet decoding requires interface zero.
    #[test]
    fn parse_rejects_simple_packet_without_interface() {
        let data = [0, 0, 0, 4, 0, 1, 2, 3];
        let err = SimplePacketBlock::from_body::<BigEndian>(&PcapNgState::default(), &data).unwrap_err();

        assert!(matches!(err, BlockValidationError::NoInterface));
    }

    /// Checks Simple Packet capture truncation and padding consumption.
    #[test]
    fn parse_truncates_simple_packet_to_snaplen_and_consumes_padding() {
        let state = state_with_snaplen(2);
        let data = [
            0, 0, 0, 4, // original_len
            0, 1, // captured packet data
            0, 0, // padding
        ];

        let (rem, packet) = SimplePacketBlock::from_body::<BigEndian>(&state, &data).unwrap();

        assert_eq!(packet.original_len, 4);
        assert_eq!(&packet.data[..], &[0, 1]);
        assert!(rem.is_empty());
    }

    /// Checks that Simple Packet validation requires interface zero.
    #[test]
    fn validate_rejects_simple_packet_without_interface() {
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1, 2, 3]),
        };
        let err = packet.validate(&PcapNgState::default()).unwrap_err();

        assert!(matches!(err, BlockValidationError::NoInterface));
    }

    /// Checks that an unlimited capture requires the complete Simple Packet payload.
    #[test]
    fn validate_rejects_simple_packet_shorter_than_expected_with_unlimited_snaplen() {
        let state = state_with_snaplen(0);
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1]),
        };
        let err = packet.validate(&state).unwrap_err();

        assert!(matches!(
            err,
            BlockValidationError::InvalidCapturedLen { expected: 4, actual: 2 }
        ));
    }

    /// Checks that a Simple Packet truncated to snaplen can be written.
    #[test]
    fn write_accepts_simple_packet_truncated_to_snaplen() {
        let state = state_with_snaplen(2);
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1]),
        };

        assert_eq!(
            packet.write_body_to::<BigEndian, _>(&state, &mut Vec::new()).unwrap(),
            8
        );
    }

    /// Checks that Simple Packet validation rejects an excessive payload length.
    #[test]
    fn validate_rejects_simple_packet_longer_than_snaplen() {
        let state = state_with_snaplen(2);
        let packet = SimplePacketBlock {
            original_len: 4,
            data: Cow::Borrowed(&[0, 1, 2]),
        };
        let err = packet.validate(&state).unwrap_err();

        assert!(matches!(
            err,
            BlockValidationError::InvalidCapturedLen { expected: 2, actual: 3 }
        ));
    }
}
