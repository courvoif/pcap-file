use std::borrow::Cow;
use std::time::Duration;

use byteorder_slice::BigEndian;
use pcap_file::DataLink;
use pcap_file::pcapng::blocks::PcapNgBlock;
use pcap_file::pcapng::blocks::block_common::{ENHANCED_PACKET_BLOCK, RawBlock};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption, InterfaceTsResolution,
};
use pcap_file::pcapng::{
    BlockContentParseError, ContentValidationError, PcapNgReadError, PcapNgReader, PcapNgWriteError, PcapNgWriter,
};

#[test]
fn writer_rejects_timestamp_before_interface_offset() {
    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 0xFFFF,
        options: vec![
            InterfaceDescriptionOption::IfTsResol(InterfaceTsResolution::NANO),
            InterfaceDescriptionOption::IfTsOffset(2),
        ],
    };
    let packet = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: Duration::from_secs(1),
        original_len: 4,
        data: Cow::Borrowed(&[0xDE, 0xAD, 0xBE, 0xEF]),
        options: vec![],
    };

    let mut writer = PcapNgWriter::new(Vec::new()).unwrap();
    writer.write_block(&interface.into_block()).unwrap();
    let error = writer.write_block(&packet.into_block()).unwrap_err();

    assert!(matches!(
        error,
        PcapNgWriteError::Validation {
            field: "EnhancedPacketBlock.timestamp",
            source,
        } if matches!(source.as_ref(), ContentValidationError::FailedToEncodeTimestamp { .. })
    ));
}

#[test]
fn negative_offset_roundtrip_accepts_timestamp_at_unix_epoch() {
    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 0xFFFF,
        options: vec![
            InterfaceDescriptionOption::IfTsResol(InterfaceTsResolution::SEC),
            InterfaceDescriptionOption::IfTsOffset(-2),
        ],
    };
    let packet = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: Duration::ZERO,
        original_len: 0,
        data: Cow::Borrowed(&[]),
        options: vec![],
    };

    let mut writer = PcapNgWriter::new(Vec::new()).unwrap();
    writer.write_block(&interface.into_block()).unwrap();
    writer.write_block(&packet.into_block()).unwrap();

    let buffer = writer.into_inner();
    let mut reader = PcapNgReader::new(&buffer[..]).unwrap();
    reader.next_block().unwrap().unwrap();
    let (block, _) = reader.next_block().unwrap().unwrap();

    assert_eq!(block.as_enhanced_packet().unwrap().timestamp, Duration::ZERO);
}

#[test]
fn reader_rejects_timestamp_before_unix_epoch() {
    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 0xFFFF,
        options: vec![
            InterfaceDescriptionOption::IfTsResol(InterfaceTsResolution::SEC),
            InterfaceDescriptionOption::IfTsOffset(-2),
        ],
    };
    let packet = RawBlock {
        type_: ENHANCED_PACKET_BLOCK,
        initial_len: 32,
        body: vec![
            0, 0, 0, 0, // interface_id
            0, 0, 0, 0, // timestamp_high
            0, 0, 0, 1, // timestamp_low: one second relative to a -2 second offset
            0, 0, 0, 0, // captured_len
            0, 0, 0, 0, // original_len
        ]
        .into(),
        trailer_len: 32,
    };

    let mut writer = PcapNgWriter::with_endianness(Vec::new(), pcap_file::Endianness::Big).unwrap();
    writer.write_block(&interface.into_block()).unwrap();
    packet.write_to::<BigEndian, _>(writer.get_mut()).unwrap();

    let buffer = writer.into_inner();
    let mut reader = PcapNgReader::new(&buffer[..]).unwrap();
    reader.next_block().unwrap().unwrap();
    let error = reader.next_block().unwrap().unwrap_err();

    assert!(matches!(
        error,
        PcapNgReadError::BlockConversion(error)
            if matches!(
                error.source.as_ref(),
                BlockContentParseError::Validation(ContentValidationError::FailedToDecodeTimestamp { .. })
            )
    ));
}
