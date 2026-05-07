use std::borrow::Cow;

use pcap_file::DataLink;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption};
use pcap_file::pcapng::blocks::{Block, PcapNgBlock};
use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};

#[test]
fn writer_roundtrip_preserves_negative_timestamp_offset() {
    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 0xFFFF,
        options: vec![InterfaceDescriptionOption::IfTsResol(9), InterfaceDescriptionOption::IfTsOffset(-2)],
    };

    let packet = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: -1_000_000_000,
        original_len: 4,
        data: Cow::Borrowed(&[0xDE, 0xAD, 0xBE, 0xEF]),
        options: vec![],
    };

    let mut buffer = Vec::new();
    let mut writer = PcapNgWriter::new(&mut buffer).expect("Failed to create writer");

    writer.write_block(&interface.into_block()).expect("Failed to write interface description block");
    writer.write_block(&packet.into_block()).expect("Failed to write enhanced packet block");

    let mut reader = PcapNgReader::new(&buffer[..]).expect("Failed to create reader");

    let (interface_block, _) = reader.next_block().expect("Missing interface block").expect("Failed to read interface block");
    match interface_block {
        Block::InterfaceDescription(block) => {
            assert!(
                block.options.contains(&InterfaceDescriptionOption::IfTsOffset(-2)),
                "Missing signed if_tsoffset option after round-trip"
            );
        },
        other => panic!("Expected an interface description block, got {other:?}"),
    }

    let (packet_block, _) = reader.next_block().expect("Missing packet block").expect("Failed to read packet block");
    match packet_block {
        Block::EnhancedPacket(block) => {
            assert_eq!(block.timestamp, -1_000_000_000, "Pre-epoch timestamp did not survive round-trip");
        },
        other => panic!("Expected an enhanced packet block, got {other:?}"),
    }
}
