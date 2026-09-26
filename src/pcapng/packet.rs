//! A common packet view for pcapng packet blocks.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::time::Duration;

use derive_into_owned::IntoOwned;

use super::blocks::Block;
use super::PcapNgState;
use crate::DataLink;
use crate::pcapng::errors::PacketConversionError;

/* ----- Packet view ----- */

/// Common packet data from an Enhanced Packet, Simple Packet, or obsolete Packet Block.
///
/// Interface IDs, options, and other block-specific metadata are not retained.
/// Use [`super::PcapNgReader::next_block`] when that metadata is needed.
#[derive(Clone, Debug, Eq, PartialEq, IntoOwned)]
pub struct PcapNgPacket<'a> {
    /// Link-layer type resolved from the packet's interface in the current section.
    pub datalink: DataLink,
    /// Packet timestamp, or [`None`] for a Simple Packet Block.
    pub timestamp: Option<Duration>,
    /// Original packet length on the wire, before capture truncation.
    pub original_len: u32,
    /// Captured packet data.
    pub data: Cow<'a, [u8]>,
}

impl<'a> PcapNgPacket<'a> {
    /// Converts a packet block using the current section's interface state.
    ///
    /// Simple Packet Blocks use interface 0.
    /// Packet data retains its ownership without copying.
    /// This resolves the datalink but does not perform semantic validation.
    ///
    /// # Errors
    ///
    /// Returns [`PacketConversionError::NotPacket`] with the original block for
    /// non-packet blocks, or [`PacketConversionError::InvalidInterfaceId`] if
    /// the packet's interface is missing.
    pub fn from_block(block: Block<'a>, state: &PcapNgState) -> Result<Self, PacketConversionError<'a>> {
        let (interface_id, timestamp, original_len, data) = match block {
            Block::EnhancedPacket(packet) => (
                packet.interface_id,
                Some(packet.timestamp),
                packet.original_len,
                packet.data,
            ),
            Block::SimplePacket(packet) => (0, None, packet.original_len, packet.data),
            Block::Packet(packet) => (
                u32::from(packet.interface_id),
                Some(packet.timestamp),
                packet.original_len,
                packet.data,
            ),
            block => return Err(PacketConversionError::NotPacket(block)),
        };

        let interface = state
            .interfaces()
            .get(interface_id as usize)
            .ok_or(PacketConversionError::InvalidInterfaceId(interface_id))?;

        Ok(Self {
            datalink: interface.linktype,
            timestamp,
            original_len,
            data,
        })
    }
}

/* ----- Tests ----- */

#[cfg(test)]
mod tests {
    /* ----- Imports ----- */

    use super::*;
    use crate::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use crate::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    use crate::pcapng::blocks::packet::PacketBlock;
    use crate::pcapng::blocks::section_header::SectionHeaderBlock;
    use crate::pcapng::blocks::simple_packet::SimplePacketBlock;

    /* ----- Test state ----- */

    fn state() -> PcapNgState {
        let mut state = PcapNgState::default();
        for datalink in [DataLink::ETHERNET, DataLink::RAW, DataLink::USER0] {
            state.update_from_block(&Block::InterfaceDescription(InterfaceDescriptionBlock::new(
                datalink, 0,
            )));
        }
        state
    }

    /* ----- Packet conversions ----- */

    #[test]
    fn packet_conversions_cover_all_packet_block_types() {
        let blocks = [
            Block::EnhancedPacket(EnhancedPacketBlock {
                interface_id: 1,
                timestamp: Duration::from_secs(1),
                original_len: 4,
                data: Cow::Borrowed(&[1, 2]),
                ..Default::default()
            }),
            Block::SimplePacket(SimplePacketBlock {
                original_len: 5,
                data: Cow::Borrowed(&[3, 4]),
            }),
            Block::Packet(PacketBlock {
                interface_id: 2,
                drop_count: 3,
                timestamp: Duration::from_secs(2),
                original_len: 6,
                data: Cow::Borrowed(&[5, 6]),
                options: Vec::new(),
            }),
        ];
        let expected = [
            (DataLink::RAW, Some(Duration::from_secs(1)), 4, [1, 2]),
            (DataLink::ETHERNET, None, 5, [3, 4]),
            (DataLink::USER0, Some(Duration::from_secs(2)), 6, [5, 6]),
        ];

        for (block, (datalink, timestamp, original_len, data)) in blocks.into_iter().zip(expected) {
            let packet = PcapNgPacket::from_block(block, &state()).unwrap();
            assert_eq!(
                packet,
                PcapNgPacket {
                    datalink,
                    timestamp,
                    original_len,
                    data: Cow::Borrowed(&data)
                }
            );
            assert_eq!(packet.datalink, datalink);
            assert_eq!(packet.timestamp, timestamp);
            assert_eq!(packet.original_len, original_len);
            assert_eq!(packet.data.as_ref(), data);
            assert_eq!(packet.data.len(), 2);
            assert!(!packet.data.is_empty());
            assert!(matches!(packet.data, Cow::Borrowed(_)));
        }
    }

    #[test]
    fn non_packet_conversion_preserves_original_block() {
        let block = Block::SectionHeader(SectionHeaderBlock::default());
        for result in [
            PcapNgPacket::from_block(block.clone(), &PcapNgState::default()),
            block.clone().into_pcapng_packet(&PcapNgState::default()),
        ] {
            assert!(matches!(result, Err(PacketConversionError::NotPacket(original)) if original == block));
        }
    }

    #[test]
    fn conversion_rejects_missing_interfaces() {
        let blocks = [
            Block::EnhancedPacket(EnhancedPacketBlock::default()),
            Block::SimplePacket(SimplePacketBlock {
                original_len: 0,
                data: Cow::Borrowed(&[]),
            }),
            Block::Packet(PacketBlock {
                interface_id: 0,
                drop_count: 0,
                timestamp: Duration::ZERO,
                original_len: 0,
                data: Cow::Borrowed(&[]),
                options: Vec::new(),
            }),
        ];
        for block in blocks {
            assert!(matches!(
                PcapNgPacket::from_block(block, &PcapNgState::default()),
                Err(PacketConversionError::InvalidInterfaceId(0))
            ));
        }

        let block = Block::EnhancedPacket(EnhancedPacketBlock {
            interface_id: 3,
            ..Default::default()
        });
        assert!(matches!(
            block.into_pcapng_packet(&state()),
            Err(PacketConversionError::InvalidInterfaceId(3))
        ));
    }

    #[test]
    fn conversion_preserves_owned_data_without_copying() {
        let data = vec![1, 2];
        let ptr = data.as_ptr();
        let packet = Block::SimplePacket(SimplePacketBlock {
            original_len: 2,
            data: Cow::Owned(data),
        })
        .into_pcapng_packet(&state())
        .unwrap();

        match packet.data {
            Cow::Owned(data) => {
                assert_eq!(data, [1, 2]);
                assert_eq!(data.as_ptr(), ptr);
            }
            Cow::Borrowed(_) => panic!("owned data should stay owned"),
        }
    }

    #[test]
    fn into_owned_detaches_borrowed_data() {
        let packet = {
            let data = [1, 2];
            PcapNgPacket {
                datalink: DataLink::RAW,
                timestamp: None,
                original_len: 3,
                data: Cow::Borrowed(&data),
            }
            .into_owned()
        };
        assert_eq!(packet.data.as_ref(), [1, 2]);
        assert_eq!(packet.original_len, 3);
        assert_eq!(packet.timestamp, None);
        assert_eq!(packet.datalink, DataLink::RAW);
        assert!(matches!(packet.data, Cow::Owned(_)));
    }

    #[test]
    fn empty_packet_has_no_captured_data() {
        let packet = PcapNgPacket {
            datalink: DataLink::ETHERNET,
            timestamp: None,
            original_len: 0,
            data: Cow::Borrowed(&[]),
        };
        assert!(packet.data.is_empty());
        assert_eq!(packet.data.len(), 0);
    }
}
