//! Checks read error positions for pcap and pcapng streams.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::error::Error;
use std::io::ErrorKind;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapReadErrorKind, PcapReader, PcapWriter, RawPcapPacket};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::blocks::opt_common::CommonOption;
use pcap_file::pcapng::blocks::section_header::{SectionHeaderBlock, SectionHeaderOption};
use pcap_file::pcapng::errors::PcapNgReadErrorKind;
use pcap_file::pcapng::{PcapNgBlock, PcapNgReader, PcapNgWriter};
use pcap_file::{DataLink, Endianness};

/* ----- Capture fixtures ----- */

/// Returns a capture with one valid and two invalid packets and their starting offsets.
fn pcap_bytes(endianness: Endianness) -> (Vec<u8>, Vec<u64>) {
    let header = PcapHeader {
        endianness,
        ..Default::default()
    };
    let mut writer = PcapWriter::with_header(Vec::new(), header).unwrap();
    let mut offsets = Vec::new();
    let mut offset = 24;

    for orig_len in [3, 1, 1] {
        offsets.push(offset);
        offset += writer
            .write_raw_packet(&RawPcapPacket {
                ts_sec: 1,
                ts_frac: 0,
                incl_len: 3,
                orig_len,
                data: Cow::Borrowed(&[1, 2, 3]),
            })
            .unwrap() as u64;
    }

    (writer.into_inner(), offsets)
}

/// Returns a capture with invalid packets at block indexes three and six across two sections.
fn pcapng_bytes(endianness: Endianness) -> (Vec<u8>, Vec<u64>) {
    let section = SectionHeaderBlock {
        endianness,
        options: vec![SectionHeaderOption::Common(CommonOption::Comment("section".into()))],
        ..Default::default()
    };
    let mut writer = PcapNgWriter::with_section_header(Vec::new(), section, false).unwrap();
    let interface = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0);
    let packet = EnhancedPacketBlock {
        timestamp: Duration::from_secs(1),
        original_len: 3,
        data: Cow::Borrowed(&[1, 2, 3]),
        ..Default::default()
    };
    let invalid = EnhancedPacketBlock {
        original_len: 1,
        ..packet.clone()
    };
    let second_section = SectionHeaderBlock {
        endianness: match endianness {
            Endianness::Big => Endianness::Little,
            Endianness::Little => Endianness::Big,
        },
        ..Default::default()
    };
    let mut offsets = vec![0];

    for block in [
        interface.clone().into_block(),
        packet.into_block(),
        invalid.clone().into_block(),
        second_section.into_block(),
        interface.into_block(),
        invalid.into_block(),
    ] {
        offsets.push(writer.get_ref().len() as u64);
        writer.write_block(&block).unwrap();
    }

    (writer.into_inner(), offsets)
}

/* ----- Initial header errors ----- */

/// Locates invalid and incomplete global headers at offset zero for both constructors.
#[test]
fn pcap_header_errors_have_a_position() {
    for input in [&[][..], &[0; 24][..]] {
        for custom_capacity in [false, true] {
            let error = if custom_capacity {
                PcapReader::with_capacity(input, 24).unwrap_err()
            } else {
                PcapReader::new(input).unwrap_err()
            };

            assert_eq!((error.packet_number, error.offset), (0, 0));
            assert!(error.is_fatal());
            assert!(error.to_string().contains("byte offset 0"));
            assert!(error.source().unwrap().downcast_ref::<PcapReadErrorKind>().is_some());
        }
    }
}

/// Locates invalid and incomplete initial Section Header Blocks at block zero, offset zero.
#[test]
fn pcapng_header_errors_have_a_position() {
    for input in [&[][..], &[0; 12][..]] {
        for custom_capacity in [false, true] {
            let error = if custom_capacity {
                PcapNgReader::with_capacity(input, 44, true).unwrap_err()
            } else {
                PcapNgReader::new(input, true).unwrap_err()
            };

            assert_eq!((error.block_number, error.offset), (0, 0));
            assert!(error.is_fatal());
            assert!(error.to_string().contains("block 0 at byte offset 0"));
            assert!(error.source().unwrap().downcast_ref::<PcapNgReadErrorKind>().is_some());
        }
    }
}

/* ----- Consumed and skipped records ----- */

/// Counts raw packets and skipped invalid packets without including buffered lookahead.
#[test]
fn pcap_error_positions_follow_consumed_packets() {
    for endianness in [Endianness::Big, Endianness::Little] {
        let (bytes, offsets) = pcap_bytes(endianness);

        for custom_capacity in [false, true] {
            let mut reader = if custom_capacity {
                PcapReader::with_capacity(bytes.as_slice(), 24).unwrap()
            } else {
                PcapReader::new(bytes.as_slice()).unwrap()
            };
            reader.next_raw_packet().unwrap().unwrap();

            for packet_number in [1, 2] {
                let error = reader.next_packet().unwrap().unwrap_err();
                assert_eq!(
                    (error.packet_number, error.offset),
                    (packet_number, offsets[packet_number as usize])
                );
                assert!(!error.is_fatal());
                assert!(matches!(error.kind, PcapReadErrorKind::Validation(_)));
            }
            assert!(reader.next_packet().is_none());
        }

        let mut packets = PcapReader::new(bytes.as_slice()).unwrap().packets();
        packets.next().unwrap().unwrap();
        for packet_number in [1, 2] {
            let error = packets.next().unwrap().unwrap_err();
            assert_eq!(
                (error.packet_number, error.offset),
                (packet_number, offsets[packet_number as usize])
            );
        }
        assert!(packets.next().is_none());
    }
}

/// Counts every block across raw reads, skipped errors, and section byte order changes.
#[test]
fn pcapng_error_positions_follow_consumed_blocks() {
    for endianness in [Endianness::Big, Endianness::Little] {
        let (bytes, offsets) = pcapng_bytes(endianness);

        for custom_capacity in [false, true] {
            let mut reader = if custom_capacity {
                PcapNgReader::with_capacity(bytes.as_slice(), 44, true).unwrap()
            } else {
                PcapNgReader::new(bytes.as_slice(), true).unwrap()
            };
            reader.next_raw_block().unwrap().unwrap();
            reader.next_block().unwrap().unwrap();
            let error = reader.next_block().unwrap().unwrap_err();
            assert_eq!((error.block_number, error.offset), (3, offsets[3]));
            assert!(!error.is_fatal());
            assert!(matches!(error.kind, PcapNgReadErrorKind::Block(_)));

            reader.next_raw_block().unwrap().unwrap();
            reader.next_block().unwrap().unwrap();
            let error = reader.next_block().unwrap().unwrap_err();
            assert_eq!((error.block_number, error.offset), (6, offsets[6]));
            assert!(reader.next_block().is_none());
        }

        let mut packets = PcapNgReader::new(bytes.as_slice(), true).unwrap().packets();
        packets.next().unwrap().unwrap();
        for block_number in [3, 6] {
            let error = packets.next().unwrap().unwrap_err();
            assert_eq!(
                (error.block_number, error.offset),
                (block_number, offsets[block_number as usize])
            );
        }
        assert!(packets.next().is_none());
    }
}

/* ----- Incomplete records ----- */

/// Reports the beginning of a truncated packet through typed and raw reads.
#[test]
fn pcap_truncation_reports_packet_start() {
    let (mut bytes, offsets) = pcap_bytes(Endianness::Big);
    bytes.truncate(offsets[2] as usize - 1);

    for raw in [false, true] {
        let mut reader = PcapReader::with_capacity(bytes.as_slice(), 24).unwrap();
        reader.next_raw_packet().unwrap().unwrap();
        let error = if raw {
            reader.next_raw_packet().unwrap().unwrap_err()
        } else {
            reader.next_packet().unwrap().unwrap_err()
        };

        assert_eq!((error.packet_number, error.offset), (1, offsets[1]));
        assert!(error.is_fatal());
        assert!(matches!(error.kind, PcapReadErrorKind::Io(error) if error.kind() == ErrorKind::UnexpectedEof));
        assert!(reader.next_packet().is_none());
    }
}

/// Reports the beginning of a truncated block through typed and raw reads.
#[test]
fn pcapng_truncation_reports_block_start() {
    let (mut bytes, offsets) = pcapng_bytes(Endianness::Big);
    bytes.truncate(offsets[3] as usize - 1);

    for raw in [false, true] {
        let mut reader = PcapNgReader::with_capacity(bytes.as_slice(), 44, true).unwrap();
        reader.next_raw_block().unwrap().unwrap();
        let error = if raw {
            reader.next_raw_block().unwrap().unwrap_err()
        } else {
            reader.next_block().unwrap().unwrap_err()
        };

        assert_eq!((error.block_number, error.offset), (2, offsets[2]));
        assert!(error.is_fatal());
        assert!(matches!(error.kind, PcapNgReadErrorKind::Io(error) if error.kind() == ErrorKind::UnexpectedEof));
        assert!(reader.next_block().is_none());
    }
}
