//! Regression tests for typed pcapng options and write error mapping.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};
use pcap_file::pcapng::blocks::custom::{CustomBinaryOption, CustomUtf8Option};
use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
use pcap_file::pcapng::blocks::interface_description::{
    IfIpv4AddrOpt, IfIpv6AddrOpt, InterfaceDescriptionBlock, InterfaceDescriptionOption, InterfaceTsResolution,
    MacAddr6, MacAddr8,
};
use pcap_file::pcapng::blocks::interface_statistics::{InterfaceStatisticsBlock, InterfaceStatisticsOption};
use pcap_file::pcapng::blocks::name_resolution::{NameResolutionBlock, NameResolutionOption};
use pcap_file::pcapng::blocks::opt_common::{CommonOption, PacketHash, UnknownOption};
use pcap_file::pcapng::blocks::packet::{PacketBlock, PacketOption};
use pcap_file::pcapng::blocks::section_header::{SectionHeaderBlock, SectionHeaderOption};
use pcap_file::pcapng::errors::{BlockValidationError, OptionEntryError, PcapNgReadErrorKind, WriteError};
use pcap_file::pcapng::{Block, PcapNgBlock, PcapNgReader, PcapNgState, PcapNgWriter};
use pcap_file::{DataLink, Endianness};

/* ----- Unknown options ----- */

/// Rejects the end marker as an unknown option code.
#[test]
fn unknown_option_rejects_zero_code() {
    assert!(matches!(
        UnknownOption::new(0, &[]),
        Err(OptionEntryError::InvalidCode(0))
    ));

    for code in [1, u16::MAX] {
        let option = UnknownOption::new(code, &[]).unwrap();
        assert_eq!(option.code.get(), code);
    }
}

/// Preserves unknown options and following known options in both byte orders.
#[test]
fn unknown_options_roundtrip() {
    for endianness in [Endianness::Big, Endianness::Little] {
        let header = SectionHeaderBlock {
            endianness,
            options: vec![
                SectionHeaderOption::Common(CommonOption::Unknown(UnknownOption::new(u16::MAX, &[]).unwrap())),
                SectionHeaderOption::Common(CommonOption::Unknown(UnknownOption::new(12345, &[1, 2, 3]).unwrap())),
                SectionHeaderOption::OS("Linux".into()),
            ],
            ..SectionHeaderBlock::default()
        };

        let writer = PcapNgWriter::with_section_header(Vec::new(), header.clone(), true).unwrap();
        let bytes = writer.into_inner();
        let reader = PcapNgReader::new(bytes.as_slice(), true).unwrap();

        assert_eq!(reader.state().section(), &header);
    }
}

/* ----- Option uniqueness ----- */

/// Rejects every supported singleton variant, including nonadjacent duplicates.
#[test]
fn singleton_options_are_rejected_when_repeated() {
    for (code, option) in [
        (2, SectionHeaderOption::Hardware("hardware".into())),
        (3, SectionHeaderOption::OS("Linux".into())),
        (4, SectionHeaderOption::UserApplication("capture".into())),
    ] {
        assert_duplicate_option(
            Block::SectionHeader(SectionHeaderBlock {
                options: vec![
                    option.clone(),
                    SectionHeaderOption::Common(CommonOption::Comment("between".into())),
                    option,
                ],
                ..SectionHeaderBlock::default()
            }),
            code,
        );
    }

    for (code, option) in [
        (2, InterfaceDescriptionOption::IfName("eth0".into())),
        (3, InterfaceDescriptionOption::IfDescription("interface".into())),
        (6, InterfaceDescriptionOption::IfMacAddr(MacAddr6::from([0; 6]))),
        (7, InterfaceDescriptionOption::IfEuIAddr(MacAddr8::from([0; 8]))),
        (8, InterfaceDescriptionOption::IfSpeed(1000)),
        (
            9,
            InterfaceDescriptionOption::IfTsResol(InterfaceTsResolution::default()),
        ),
        (10, InterfaceDescriptionOption::IfTzone(0)),
        (11, InterfaceDescriptionOption::IfFilter(Cow::Borrowed(&[0]))),
        (12, InterfaceDescriptionOption::IfOs("Linux".into())),
        (13, InterfaceDescriptionOption::IfFcsLen(32)),
        (14, InterfaceDescriptionOption::IfTsOffset(0)),
        (15, InterfaceDescriptionOption::IfHardware("hardware".into())),
    ] {
        assert_duplicate_option(
            Block::InterfaceDescription(InterfaceDescriptionBlock {
                options: vec![
                    option.clone(),
                    InterfaceDescriptionOption::Common(CommonOption::Comment("between".into())),
                    option,
                ],
                ..InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0)
            }),
            code,
        );
    }

    for (code, option) in [
        (2, InterfaceStatisticsOption::IsbStartTime(Duration::ZERO)),
        (3, InterfaceStatisticsOption::IsbEndTime(Duration::ZERO)),
        (4, InterfaceStatisticsOption::IsbIfRecv(0)),
        (5, InterfaceStatisticsOption::IsbIfDrop(0)),
        (6, InterfaceStatisticsOption::IsbFilterAccept(0)),
        (7, InterfaceStatisticsOption::IsbOsDrop(0)),
        (8, InterfaceStatisticsOption::IsbUsrDeliv(0)),
    ] {
        assert_duplicate_option(
            Block::InterfaceStatistics(InterfaceStatisticsBlock {
                interface_id: 0,
                timestamp: Duration::ZERO,
                options: vec![
                    option.clone(),
                    InterfaceStatisticsOption::Common(CommonOption::Comment("between".into())),
                    option,
                ],
            }),
            code,
        );
    }

    for (code, option) in [
        (2, NameResolutionOption::NsDnsName("dns".into())),
        (3, NameResolutionOption::NsDnsIpv4Addr(Ipv4Addr::LOCALHOST)),
        (4, NameResolutionOption::NsDnsIpv6Addr(Ipv6Addr::LOCALHOST)),
    ] {
        assert_duplicate_option(
            Block::NameResolution(NameResolutionBlock {
                records: vec![],
                options: vec![
                    option.clone(),
                    NameResolutionOption::Common(CommonOption::Comment("between".into())),
                    option,
                ],
            }),
            code,
        );
    }

    for (code, option) in [
        (2, EnhancedPacketOption::Flags(0)),
        (4, EnhancedPacketOption::DropCount(0)),
    ] {
        assert_duplicate_option(
            Block::EnhancedPacket(EnhancedPacketBlock {
                options: vec![
                    option.clone(),
                    EnhancedPacketOption::Common(CommonOption::Comment("between".into())),
                    option,
                ],
                ..EnhancedPacketBlock::default()
            }),
            code,
        );
    }

    assert_duplicate_option(
        Block::Packet(PacketBlock {
            interface_id: 0,
            drop_count: 0,
            timestamp: Duration::ZERO,
            original_len: 0,
            data: Cow::Borrowed(&[]),
            options: vec![
                PacketOption::Flags(0),
                PacketOption::Common(CommonOption::Comment("between".into())),
                PacketOption::Flags(0),
            ],
        }),
        2,
    );
}

/// Checks duplicate errors, writer output and state, and reader validation modes.
fn assert_duplicate_option(block: Block<'_>, code: u16) {
    let mut writer = PcapNgWriter::new(Vec::new(), true).unwrap();
    writer
        .write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0))
        .unwrap();

    let error = block.validate(writer.state()).unwrap_err();
    let BlockValidationError::Option(error) = error.source.as_ref() else {
        panic!("expected a duplicate option error");
    };
    assert!(error.to_string().contains(&format!("Code: {code},")));
    let source = std::error::Error::source(error)
        .unwrap()
        .downcast_ref::<Box<OptionEntryError>>()
        .unwrap();
    assert!(matches!(source.as_ref(), OptionEntryError::Duplicate));

    let previous_bytes = writer.get_ref().clone();
    let previous_section = writer.state().section().clone();
    let previous_interfaces = writer.state().interfaces().to_vec();
    assert!(writer.write_block(&block).is_err());
    assert_eq!(writer.get_ref(), &previous_bytes);
    assert_eq!(writer.state().section(), &previous_section);
    assert_eq!(writer.state().interfaces(), previous_interfaces);

    let mut writer = PcapNgWriter::new(Vec::new(), false).unwrap();
    writer
        .write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0))
        .unwrap();
    writer.write_block(&block).unwrap();
    let bytes = writer.into_inner();

    for strict in [false, true] {
        let mut reader = PcapNgReader::new(bytes.as_slice(), strict).unwrap();
        assert!(matches!(
            reader.next_block().unwrap().unwrap().0,
            Block::InterfaceDescription(_)
        ));

        if strict {
            let error = reader.next_block().unwrap().unwrap_err();
            let changes_state = matches!(&block, Block::SectionHeader(_) | Block::InterfaceDescription(_));
            assert_eq!(error.is_fatal(), changes_state);
            assert_eq!(reader.poisoned(), changes_state);
            if changes_state {
                assert!(matches!(error.kind, PcapNgReadErrorKind::StateUpdate(_)));
                assert!(reader.next_block().is_none());
            } else {
                assert!(matches!(error.kind, PcapNgReadErrorKind::Block(_)));
            }
            assert_eq!(reader.state().section(), &previous_section);
            assert_eq!(reader.state().interfaces(), previous_interfaces);
        } else {
            assert_eq!(reader.next_block().unwrap().unwrap().0, block);
        }
    }
}

/// Preserves repeated common options, addresses, and hashes in both byte orders.
#[test]
fn repeatable_options_roundtrip() {
    let common = [
        CommonOption::Comment("comment".into()),
        CommonOption::CustomBinaryCopiable(CustomBinaryOption {
            pen: 32473,
            value: Cow::Borrowed(&[1]),
        }),
        CommonOption::CustomBinaryNonCopiable(CustomBinaryOption {
            pen: 32473,
            value: Cow::Borrowed(&[2]),
        }),
        CommonOption::CustomUtf8Copiable(CustomUtf8Option {
            pen: 32473,
            value: "copiable".into(),
        }),
        CommonOption::CustomUtf8NonCopiable(CustomUtf8Option {
            pen: 32473,
            value: "non-copiable".into(),
        }),
        CommonOption::Unknown(UnknownOption::new(u16::MAX, &[3]).unwrap()),
    ];
    let common: Vec<_> = common.into_iter().flat_map(|option| [option.clone(), option]).collect();

    for endianness in [Endianness::Big, Endianness::Little] {
        let header = SectionHeaderBlock {
            endianness,
            options: common.iter().cloned().map(SectionHeaderOption::Common).collect(),
            ..SectionHeaderBlock::default()
        };
        let mut interface = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0);
        interface.options = common.iter().cloned().map(InterfaceDescriptionOption::Common).collect();
        let ipv4 = InterfaceDescriptionOption::IfIpv4Addr(IfIpv4AddrOpt {
            ip: Ipv4Addr::LOCALHOST,
            netmask: [255, 0, 0, 0],
        });
        let ipv6 = InterfaceDescriptionOption::IfIpv6Addr(IfIpv6AddrOpt::new(Ipv6Addr::LOCALHOST, 128).unwrap());
        interface.options.extend([ipv4.clone(), ipv4, ipv6.clone(), ipv6]);

        let mut names = NameResolutionBlock {
            records: vec![],
            options: common.iter().cloned().map(NameResolutionOption::Common).collect(),
        };
        names.options.extend([
            NameResolutionOption::NsDnsName("dns".into()),
            NameResolutionOption::NsDnsIpv4Addr(Ipv4Addr::LOCALHOST),
            NameResolutionOption::NsDnsIpv6Addr(Ipv6Addr::LOCALHOST),
        ]);
        let mut statistics = InterfaceStatisticsBlock {
            interface_id: 0,
            timestamp: Duration::ZERO,
            options: common.iter().cloned().map(InterfaceStatisticsOption::Common).collect(),
        };
        statistics.options.extend([
            InterfaceStatisticsOption::IsbIfRecv(1),
            InterfaceStatisticsOption::IsbIfDrop(0),
        ]);

        let hash = PacketHash::Crc32([1, 2, 3, 4]);
        let mut enhanced = EnhancedPacketBlock {
            options: common.iter().cloned().map(EnhancedPacketOption::Common).collect(),
            ..EnhancedPacketBlock::default()
        };
        enhanced.options.extend([
            EnhancedPacketOption::Hash(hash.clone()),
            EnhancedPacketOption::Hash(hash.clone()),
            EnhancedPacketOption::Flags(0),
            EnhancedPacketOption::DropCount(0),
        ]);
        let mut packet = PacketBlock {
            interface_id: 0,
            drop_count: 0,
            timestamp: Duration::ZERO,
            original_len: 0,
            data: Cow::Borrowed(&[]),
            options: common.iter().cloned().map(PacketOption::Common).collect(),
        };
        packet.options.extend([
            PacketOption::Hash(hash.clone()),
            PacketOption::Hash(hash),
            PacketOption::Flags(0),
        ]);

        let blocks = [
            Block::InterfaceDescription(interface),
            Block::NameResolution(names),
            Block::InterfaceStatistics(statistics),
            Block::EnhancedPacket(enhanced),
            Block::Packet(packet),
        ];
        let mut writer = PcapNgWriter::with_section_header(Vec::new(), header.clone(), true).unwrap();
        for block in &blocks {
            writer.write_block(block).unwrap();
        }

        let bytes = writer.into_inner();
        let mut reader = PcapNgReader::new(bytes.as_slice(), true).unwrap();
        assert_eq!(reader.state().section(), &header);
        for block in blocks {
            assert_eq!(reader.next_block().unwrap().unwrap().0, block);
        }
        assert!(reader.next_block().is_none());
    }
}

/// Leaves raw unknown options unchecked even when their code matches a known singleton.
#[test]
fn unknown_options_do_not_count_as_singletons() {
    let unknown = InterfaceDescriptionOption::Common(CommonOption::Unknown(UnknownOption::new(9, &[6]).unwrap()));
    let interface = InterfaceDescriptionBlock {
        options: vec![
            unknown.clone(),
            InterfaceDescriptionOption::IfTsResol(InterfaceTsResolution::default()),
            unknown,
        ],
        ..InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0)
    };
    interface.validate(&PcapNgState::default()).unwrap();
}

/* ----- Address options ----- */

/// Preserves each fixed-size address option through writing and reading.
#[test]
fn address_options_roundtrip() {
    for endianness in [Endianness::Big, Endianness::Little] {
        let header = SectionHeaderBlock {
            endianness,
            ..SectionHeaderBlock::default()
        };
        let interface = Block::InterfaceDescription(InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0,
            options: vec![
                InterfaceDescriptionOption::IfIpv4Addr(IfIpv4AddrOpt {
                    ip: Ipv4Addr::new(192, 0, 2, 1),
                    netmask: [255, 255, 255, 0],
                }),
                InterfaceDescriptionOption::IfIpv6Addr(
                    IfIpv6AddrOpt::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 64).unwrap(),
                ),
                InterfaceDescriptionOption::IfMacAddr(MacAddr6::from([0, 1, 2, 3, 4, 5])),
                InterfaceDescriptionOption::IfEuIAddr(MacAddr8::from([2, 0x34, 0x56, 0xff, 0xfe, 0x78, 0x9a, 0xbc])),
                InterfaceDescriptionOption::IfFilter((&[0, b't', b'c', b'p'][..]).into()),
            ],
        });
        let names = Block::NameResolution(NameResolutionBlock {
            records: vec![],
            options: vec![
                NameResolutionOption::NsDnsIpv4Addr(Ipv4Addr::new(192, 0, 2, 53)),
                NameResolutionOption::NsDnsIpv6Addr(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53)),
            ],
        });

        let mut writer = PcapNgWriter::with_section_header(Vec::new(), header, true).unwrap();
        writer.write_block(&interface).unwrap();
        writer.write_block(&names).unwrap();
        let bytes = writer.into_inner();
        let mut reader = PcapNgReader::new(bytes.as_slice(), true).unwrap();

        assert_eq!(reader.next_block().unwrap().unwrap().0, interface);
        assert_eq!(reader.next_block().unwrap().unwrap().0, names);
        assert!(reader.next_block().is_none());
    }
}

/// Encodes hardware addresses in address order regardless of section byte order.
#[test]
fn hardware_address_options_preserve_wire_order() {
    let mac = [0, 1, 2, 3, 4, 5];
    let eui = [2, 0x34, 0x56, 0xff, 0xfe, 0x78, 0x9a, 0xbc];
    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 0,
        options: vec![
            InterfaceDescriptionOption::IfMacAddr(MacAddr6::from(mac)),
            InterfaceDescriptionOption::IfEuIAddr(MacAddr8::from(eui)),
        ],
    };
    let state = PcapNgState::default();

    for endianness in [Endianness::Big, Endianness::Little] {
        let mut body = Vec::new();
        let (written, parsed) = match endianness {
            Endianness::Big => {
                let written = interface.write_body_to::<BigEndian, _>(&state, &mut body).unwrap();
                let (_, parsed) = InterfaceDescriptionBlock::from_body::<BigEndian>(&state, &body).unwrap();
                (written, parsed)
            }
            Endianness::Little => {
                let written = interface.write_body_to::<LittleEndian, _>(&state, &mut body).unwrap();
                let (_, parsed) = InterfaceDescriptionBlock::from_body::<LittleEndian>(&state, &body).unwrap();
                (written, parsed)
            }
        };

        assert_eq!(written, 36);
        assert_eq!(body.len(), written);
        assert_eq!(&body[12..18], &mac);
        assert_eq!(&body[18..20], &[0, 0]);
        assert_eq!(&body[24..32], &eui);
        assert_eq!(parsed, interface);
    }
}

/// Rejects truncated and oversized address values before constructing typed options.
#[test]
fn address_options_reject_wrong_wire_lengths() {
    let state = PcapNgState::default();

    for (interface, code, expected) in [
        (true, 4_u16, 8),
        (true, 5, 17),
        (true, 6, 6),
        (true, 7, 8),
        (false, 3, 4),
        (false, 4, 16),
    ] {
        for actual in [expected - 1, expected + 1] {
            let mut body = vec![0; if interface { 8 } else { 4 }];
            body.extend_from_slice(&code.to_be_bytes());
            body.extend_from_slice(&(actual as u16).to_be_bytes());
            body.resize(body.len() + actual + (4 - actual % 4) % 4, 0);

            let error = if interface {
                InterfaceDescriptionBlock::from_body::<BigEndian>(&state, &body).unwrap_err()
            } else {
                NameResolutionBlock::from_body::<BigEndian>(&state, &body).unwrap_err()
            };

            let BlockValidationError::Option(error) = error else {
                panic!("expected an option error");
            };
            let source = std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<Box<OptionEntryError>>()
                .unwrap();
            assert!(matches!(
                source.as_ref(),
                OptionEntryError::WrongSize { expected: size, actual: length }
                    if *size == expected && *length == actual
            ));
        }
    }
}

/* ----- IPv6 prefix lengths ----- */

/// Accepts every valid prefix length and rejects out-of-range lengths when constructing or parsing.
#[test]
fn ipv6_prefix_lengths_enforce_address_width() {
    let ip = Ipv6Addr::LOCALHOST;

    for prefix_len in 0..=u8::MAX {
        let mut value = ip.octets().to_vec();
        value.push(prefix_len);
        let constructed = IfIpv6AddrOpt::new(ip, prefix_len);
        let parsed = IfIpv6AddrOpt::from_slice(&value);

        if prefix_len <= 128 {
            let address = constructed.unwrap();
            assert_eq!(address.ip, ip);
            assert_eq!(address.prefix_len(), prefix_len);
            assert_eq!(parsed.unwrap(), address);
        } else {
            assert!(matches!(constructed, Err(OptionEntryError::InvalidIpv6PrefixLen(actual)) if actual == prefix_len));
            assert!(matches!(parsed, Err(OptionEntryError::InvalidIpv6PrefixLen(actual)) if actual == prefix_len));
        }
    }
}

/// Reports invalid IPv6 prefixes as option errors in both section byte orders.
#[test]
fn ipv6_address_options_reject_invalid_prefix_lengths() {
    let state = PcapNgState::default();

    for endianness in [Endianness::Big, Endianness::Little] {
        for prefix_len in [129, 255] {
            let mut body = vec![0; 8];
            match endianness {
                Endianness::Big => body.extend_from_slice(&[0, 5, 0, 17]),
                Endianness::Little => body.extend_from_slice(&[5, 0, 17, 0]),
            }
            body.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            body.push(prefix_len);
            body.extend_from_slice(&[0; 3]);

            let error = match endianness {
                Endianness::Big => InterfaceDescriptionBlock::from_body::<BigEndian>(&state, &body).unwrap_err(),
                Endianness::Little => InterfaceDescriptionBlock::from_body::<LittleEndian>(&state, &body).unwrap_err(),
            };
            let BlockValidationError::Option(error) = error else {
                panic!("expected an IPv6 option error");
            };
            let source = std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<Box<OptionEntryError>>()
                .unwrap();
            assert!(matches!(source.as_ref(), OptionEntryError::InvalidIpv6PrefixLen(actual) if *actual == prefix_len));
        }
    }
}

/* ----- Packet hashes ----- */

/// Preserves supported and unsupported hashes in both packet block types and byte orders.
#[test]
fn packet_hash_options_roundtrip() {
    check_packet_hash_options::<BigEndian>();
    check_packet_hash_options::<LittleEndian>();
}

/// Checks digest bytes, framing, padding, and ownership for both packet block types.
fn check_packet_hash_options<B: ByteOrder>() {
    let mut state = PcapNgState::default();
    state.update_from_block(&Block::InterfaceDescription(InterfaceDescriptionBlock::new(
        DataLink::ETHERNET,
        0,
    )));

    let cases = [
        (
            PacketHash::Crc32([0xec, 0x1d, 0x87, 0x97]),
            vec![2, 0xec, 0x1d, 0x87, 0x97],
        ),
        (PacketHash::Md5([0x23; 16]), [vec![3], vec![0x23; 16]].concat()),
        (PacketHash::Sha1([0x45; 20]), [vec![4], vec![0x45; 20]].concat()),
        (PacketHash::Toeplitz([0x67; 4]), vec![5, 0x67, 0x67, 0x67, 0x67]),
        (
            PacketHash::Unknown {
                algorithm: 0,
                value: Cow::Borrowed(&[1, 2]),
            },
            vec![0, 1, 2],
        ),
        (
            PacketHash::Unknown {
                algorithm: 1,
                value: Cow::Borrowed(&[3]),
            },
            vec![1, 3],
        ),
        (
            PacketHash::Unknown {
                algorithm: 255,
                value: Cow::Borrowed(&[]),
            },
            vec![255],
        ),
        (
            PacketHash::Unknown {
                algorithm: 42,
                value: Cow::Borrowed(&[4, 5, 6, 7]),
            },
            vec![42, 4, 5, 6, 7],
        ),
    ];

    for (hash, wire_value) in cases {
        let enhanced = EnhancedPacketBlock {
            options: vec![EnhancedPacketOption::Hash(hash.clone())],
            ..EnhancedPacketBlock::default()
        };
        let packet = PacketBlock {
            interface_id: 0,
            drop_count: 0,
            timestamp: std::time::Duration::ZERO,
            original_len: 0,
            data: Cow::Borrowed(&[]),
            options: vec![PacketOption::Hash(hash)],
        };

        let mut enhanced_body = Vec::new();
        let enhanced_written = enhanced.write_body_to::<B, _>(&state, &mut enhanced_body).unwrap();
        let (remaining, enhanced_parsed) = EnhancedPacketBlock::from_body::<B>(&state, &enhanced_body).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(enhanced_parsed.into_owned(), enhanced);

        let mut packet_body = Vec::new();
        let packet_written = packet.write_body_to::<B, _>(&state, &mut packet_body).unwrap();
        let (remaining, packet_parsed) = PacketBlock::from_body::<B>(&state, &packet_body).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(packet_parsed.into_owned(), packet);

        let padded_len = wire_value.len().div_ceil(4) * 4;
        for (body, written) in [(enhanced_body, enhanced_written), (packet_body, packet_written)] {
            assert_eq!(written, 20 + 4 + padded_len + 4);
            assert_eq!(body.len(), written);
            assert_eq!(&body[24..24 + wire_value.len()], wire_value);
            assert!(body[24 + wire_value.len()..].iter().all(|byte| *byte == 0));
        }
    }
}

/// Rejects missing algorithm bytes and wrong digest lengths in either packet block type.
#[test]
fn packet_hash_options_reject_invalid_wire_values() {
    let mut state = PcapNgState::default();
    state.update_from_block(&Block::InterfaceDescription(InterfaceDescriptionBlock::new(
        DataLink::ETHERNET,
        0,
    )));

    let mut values = vec![vec![]];
    for (algorithm, digest_len) in [(2, 4), (3, 16), (4, 20), (5, 4)] {
        for actual in [0, digest_len - 1, digest_len + 1] {
            let mut value = vec![algorithm];
            value.resize(actual + 1, 0);
            values.push(value);
        }
    }

    for value in values {
        let mut body = vec![0; 20];
        body.extend_from_slice(&3_u16.to_be_bytes());
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(&value);
        body.resize(body.len() + (4 - value.len() % 4) % 4, 0);

        for error in [
            EnhancedPacketBlock::from_body::<BigEndian>(&state, &body).unwrap_err(),
            PacketBlock::from_body::<BigEndian>(&state, &body).unwrap_err(),
        ] {
            let BlockValidationError::Option(error) = error else {
                panic!("expected a hash option error");
            };
            let source = std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<Box<OptionEntryError>>()
                .unwrap();

            if value.is_empty() {
                assert!(matches!(
                    source.as_ref(),
                    OptionEntryError::ContentTooSmall { needed: 1, actual: 0 }
                ));
            } else {
                let expected = match value[0] {
                    2 => 5,
                    3 => 17,
                    4 => 21,
                    5 => 5,
                    _ => unreachable!(),
                };
                assert!(matches!(
                    source.as_ref(),
                    OptionEntryError::WrongSize { expected: size, actual }
                        if *size == expected && *actual == value.len()
                ));
            }
        }
    }
}

/* ----- Variable-length option validation ----- */

/// Rejects an empty filter without writing bytes or adding an interface to the state.
#[test]
fn empty_filter_is_rejected_before_writing() {
    for strict in [false, true] {
        let mut writer = PcapNgWriter::new(Vec::new(), strict).unwrap();
        let previous_bytes = writer.get_ref().clone();
        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0,
            options: vec![InterfaceDescriptionOption::IfFilter((&[][..]).into())],
        };

        assert!(writer.write_pcapng_block(interface).is_err());
        assert_eq!(writer.get_ref(), &previous_bytes);
        assert!(writer.state().interfaces().is_empty());
    }
}

/// Reports the missing filter type byte when reading an empty filter.
#[test]
fn empty_filter_is_rejected_when_parsing() {
    let body = [0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0];
    let error = InterfaceDescriptionBlock::from_body::<BigEndian>(&PcapNgState::default(), &body).unwrap_err();
    let BlockValidationError::Option(error) = error else {
        panic!("expected an option error");
    };

    let source = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<Box<OptionEntryError>>()
        .unwrap();
    assert!(matches!(
        source.as_ref(),
        OptionEntryError::ContentTooSmall { needed: 1, actual: 0 }
    ));
}

/* ----- Write error mapping ----- */

/// Preserves I/O error details and maps domain errors.
#[test]
fn write_error_mapping_preserves_io_errors() {
    let error = WriteError::<OptionEntryError>::Io(Error::new(ErrorKind::BrokenPipe, "closed writer"));
    let mapped = error.map_other(|_| -> BlockValidationError { panic!("I/O errors must not be mapped") });
    let WriteError::Io(error) = mapped else {
        panic!("expected an I/O error");
    };
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    assert_eq!(error.to_string(), "closed writer");

    let error = WriteError::Other(OptionEntryError::InvalidCode(0));
    let mapped = error.map_other(|source| Error::new(ErrorKind::InvalidData, source));
    let WriteError::Other(error) = mapped else {
        panic!("expected a domain error");
    };
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(matches!(
        error.get_ref().unwrap().downcast_ref::<OptionEntryError>(),
        Some(OptionEntryError::InvalidCode(0))
    ));
}
