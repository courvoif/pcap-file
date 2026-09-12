use std::borrow::Cow;
use std::time::Duration;

use derive_into_owned::IntoOwned;

use super::blocks::Block;
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::packet::PacketBlock;
use super::blocks::simple_packet::SimplePacketBlock;

/// A packet read from any pcapng packet block type.
#[derive(Clone, Debug, Eq, PartialEq, IntoOwned)]
pub enum PcapNgPacket<'a> {
    /// A packet from an Enhanced Packet Block.
    Enhanced(EnhancedPacketBlock<'a>),
    /// A packet from a Simple Packet Block.
    Simple(SimplePacketBlock<'a>),
    /// A packet from the obsolete Packet Block format.
    Packet(PacketBlock<'a>),
}

/// The result of classifying a pcapng [`Block`] as a packet block or another
/// block type.
#[derive(Clone, Debug, Eq, PartialEq, IntoOwned)]
pub enum PcapNgPacketOrBlock<'a> {
    /// An Enhanced Packet, Simple Packet, or obsolete Packet Block.
    Packet(PcapNgPacket<'a>),
    /// Any other pcapng block.
    Block(Block<'a>),
}

impl<'a> PcapNgPacket<'a> {
    /// Classifies a [`Block`] as a packet or another block type.
    ///
    /// The original block is preserved in [`PcapNgPacketOrBlock::Block`] when
    /// it is not an Enhanced Packet, Simple Packet, or obsolete Packet Block.
    pub fn from_block(block: Block<'a>) -> PcapNgPacketOrBlock<'a> {
        match block {
            Block::EnhancedPacket(packet) => PcapNgPacketOrBlock::Packet(Self::Enhanced(packet)),
            Block::SimplePacket(packet) => PcapNgPacketOrBlock::Packet(Self::Simple(packet)),
            Block::Packet(packet) => PcapNgPacketOrBlock::Packet(Self::Packet(packet)),
            block => PcapNgPacketOrBlock::Block(block),
        }
    }

    /// Returns the packet data as a slice.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Enhanced(packet) => &packet.data,
            Self::Simple(packet) => &packet.data,
            Self::Packet(packet) => &packet.data,
        }
    }

    /// Returns the packet data, preserving whether it is borrowed or owned.
    pub fn into_data(self) -> Cow<'a, [u8]> {
        match self {
            Self::Enhanced(packet) => packet.data,
            Self::Simple(packet) => packet.data,
            Self::Packet(packet) => packet.data,
        }
    }

    /// Returns the captured packet data length.
    pub fn len(&self) -> usize {
        self.data().len()
    }

    /// Returns whether the packet contains no captured data.
    pub fn is_empty(&self) -> bool {
        self.data().is_empty()
    }

    /// Returns the interface ID.
    ///
    /// Returns 0 for a Simple Packet Block, which implicitly uses the first
    /// interface in the section.
    pub fn interface_id(&self) -> u32 {
        match self {
            Self::Enhanced(packet) => packet.interface_id,
            Self::Simple(_) => 0,
            Self::Packet(packet) => packet.interface_id.into(),
        }
    }

    /// Returns the packet timestamp, or [`None`] for a Simple Packet Block.
    pub fn timestamp(&self) -> Option<Duration> {
        match self {
            Self::Enhanced(packet) => Some(packet.timestamp),
            Self::Simple(_) => None,
            Self::Packet(packet) => Some(packet.timestamp),
        }
    }

    /// Returns the packet's original length on the wire.
    pub fn original_len(&self) -> u32 {
        match self {
            Self::Enhanced(packet) => packet.original_len,
            Self::Simple(packet) => packet.original_len,
            Self::Packet(packet) => packet.original_len,
        }
    }
}

impl<'a> From<EnhancedPacketBlock<'a>> for PcapNgPacket<'a> {
    fn from(value: EnhancedPacketBlock<'a>) -> Self {
        Self::Enhanced(value)
    }
}

impl<'a> From<SimplePacketBlock<'a>> for PcapNgPacket<'a> {
    fn from(value: SimplePacketBlock<'a>) -> Self {
        Self::Simple(value)
    }
}

impl<'a> From<PacketBlock<'a>> for PcapNgPacket<'a> {
    fn from(value: PacketBlock<'a>) -> Self {
        Self::Packet(value)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::Duration;

    use super::{PcapNgPacket, PcapNgPacketOrBlock};
    use crate::pcapng::blocks::Block;
    use crate::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use crate::pcapng::blocks::packet::PacketBlock;
    use crate::pcapng::blocks::section_header::SectionHeaderBlock;
    use crate::pcapng::blocks::simple_packet::SimplePacketBlock;

    #[test]
    fn block_classification_preserves_packets_and_other_blocks() {
        let packet = EnhancedPacketBlock::default();
        assert!(matches!(
            Block::EnhancedPacket(packet).into_pcapng_packet(),
            PcapNgPacketOrBlock::Packet(PcapNgPacket::Enhanced(_))
        ));

        let packet = SimplePacketBlock {
            original_len: 0,
            data: Cow::Borrowed(&[]),
        };
        assert!(matches!(
            PcapNgPacket::from_block(Block::SimplePacket(packet)),
            PcapNgPacketOrBlock::Packet(PcapNgPacket::Simple(_))
        ));

        let packet = PacketBlock {
            interface_id: 0,
            drop_count: 0,
            timestamp: Duration::ZERO,
            original_len: 0,
            data: Cow::Borrowed(&[]),
            options: Vec::new(),
        };
        assert!(matches!(
            PcapNgPacket::from_block(Block::Packet(packet)),
            PcapNgPacketOrBlock::Packet(PcapNgPacket::Packet(_))
        ));

        assert!(matches!(
            Block::SectionHeader(SectionHeaderBlock::default()).into_pcapng_packet(),
            PcapNgPacketOrBlock::Block(Block::SectionHeader(_))
        ));
    }

    #[test]
    fn packet_accessors_cover_all_packet_block_types() {
        let enhanced = PcapNgPacket::from(EnhancedPacketBlock {
            timestamp: Duration::from_secs(1),
            original_len: 4,
            data: Cow::Borrowed(&[1, 2]),
            ..Default::default()
        });
        assert_eq!(enhanced.data(), [1, 2]);
        assert_eq!(enhanced.len(), 2);
        assert!(!enhanced.is_empty());
        assert_eq!(enhanced.interface_id(), 0);
        assert_eq!(enhanced.timestamp(), Some(Duration::from_secs(1)));
        assert_eq!(enhanced.original_len(), 4);

        let simple = PcapNgPacket::from(SimplePacketBlock {
            original_len: 5,
            data: Cow::Borrowed(&[3, 4]),
        });
        assert_eq!(simple.data(), [3, 4]);
        assert_eq!(simple.len(), 2);
        assert!(!simple.is_empty());
        assert_eq!(simple.interface_id(), 0);
        assert_eq!(simple.timestamp(), None);
        assert_eq!(simple.original_len(), 5);

        let packet = PcapNgPacket::from(PacketBlock {
            interface_id: 0,
            drop_count: 0,
            timestamp: Duration::from_secs(2),
            original_len: 6,
            data: Cow::Borrowed(&[5, 6]),
            options: Vec::new(),
        });
        assert_eq!(packet.data(), [5, 6]);
        assert_eq!(packet.len(), 2);
        assert!(!packet.is_empty());
        assert_eq!(packet.interface_id(), 0);
        assert_eq!(packet.timestamp(), Some(Duration::from_secs(2)));
        assert_eq!(packet.original_len(), 6);
    }

    #[test]
    fn into_data_preserves_ownership() {
        let packet = PcapNgPacket::from(SimplePacketBlock {
            original_len: 2,
            data: Cow::Owned(vec![1, 2]),
        });

        assert!(matches!(packet.into_data(), Cow::Owned(data) if data == [1, 2]));
    }
}
