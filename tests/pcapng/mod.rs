use std::fs::File;
use std::io::Read;

use byteorder_slice::ByteOrder;
use glob::glob;
use pcap_file::pcapng::{ContentValidationError, PcapNgParser, PcapNgReader, PcapNgWriter};

#[test]
fn reader() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let file = File::open(&entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(file).unwrap();

        let mut i = 0;
        while let Some(block) = pcapng_reader.next_block() {
            let _block = block.unwrap_or_else(|_| panic!("Error on block {i} on file: {entry:?}"));
            i += 1;
        }
    }
}

#[test]
fn parser() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let mut file = File::open(&entry).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut src = &data[..];
        let (rem, mut pcapng_parser) = PcapNgParser::new(src).unwrap();
        src = rem;

        let mut i = 0;
        loop {
            if src.is_empty() {
                break;
            }

            let (rem, _) = pcapng_parser.next_block(src).unwrap_or_else(|_| panic!("Error on block {i} on file: {entry:?}"));
            src = rem;

            i += 1;
        }
    }
}

#[test]
fn writer() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let pcapng_in = std::fs::read(&entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(&pcapng_in[..]).unwrap();
        let mut pcapng_writer = PcapNgWriter::with_section_header(Vec::new(), pcapng_reader.section().clone()).unwrap();

        let mut idx = 0;
        while let Some(block) = pcapng_reader.next_block() {
            let (block, _) = block.unwrap();
            pcapng_writer
                .write_block(&block)
                .unwrap_or_else(|_| panic!("Error writing block, file: {entry:?}, block n°{idx}, block: {block:?}"));
            idx += 1;
        }

        let expected = &pcapng_in;
        let actual = pcapng_writer.get_ref();

        if expected != actual {
            let mut expected_reader = PcapNgReader::new(&expected[..]).unwrap();
            let mut actual_reader = PcapNgReader::new(&actual[..]).unwrap();

            let mut idx = 0;
            while let (Some(expected), Some(actual)) = (expected_reader.next_block(), actual_reader.next_block()) {
                let (expected, _) = expected.unwrap();
                let (actual, _) = actual.unwrap();

                if expected != actual {
                    assert_eq!(expected, actual, "Pcap written != pcap read, file: {entry:?}, block n°{idx}")
                }

                idx += 1;
            }

            panic!("Pcap written != pcap read  but blocks are equal, file: {entry:?}");
        }
    }
}

#[test]
fn test_custom_block() {
    use byteorder_slice::{
        BigEndian,
        byteorder::{ReadBytesExt, WriteBytesExt},
    };
    use pcap_file::pcapng::blocks::{custom::*, opt_common::*, section_header::*, *};
    use std::io::{Error as IoError, Write};

    // 1. Define a new custom block payload
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MyCustomPayload {
        magic_number: u64,
    }

    // 2. Implement the required traits for the custom payload
    impl CustomPayloadCopiable<'_> for MyCustomPayload {
        // A unique PEN for our test block
        const PEN: u32 = 70000;
        type WriteToError = IoError;
        type FromSliceError = IoError;

        fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), IoError> {
            writer.write_u64::<BigEndian>(self.magic_number)?;
            Ok(())
        }

        fn from_slice(slice: &[u8]) -> Result<Option<MyCustomPayload>, IoError> {
            let mut cursor = std::io::Cursor::new(slice);
            let magic_number = cursor.read_u64::<BigEndian>()?;
            Ok(Some(MyCustomPayload { magic_number }))
        }
    }

    impl CustomPayloadBlock<'_> for MyCustomPayload {}
    impl CustomPayloadOption<'_> for MyCustomPayload {}

    let original_payload = MyCustomPayload { magic_number: 0xDEADBEEFCAFED00D };

    let section = SectionHeaderBlock {
        options: vec![SectionHeaderOption::Common(
            original_payload
                .clone()
                .into_custom_binary_option_copiable()
                .expect("Failed to encode custom option")
                .into_common_option(),
        )],
        ..Default::default()
    };

    let mut buffer = Vec::new();
    let mut pcapng_writer = PcapNgWriter::with_section_header(&mut buffer, section).expect("Failed to create writer");

    let block_to_write = original_payload
        .clone()
        .into_custom_block_copiable()
        .expect("Failed to encode custom block")
        .into_block();

    pcapng_writer.write_block(&block_to_write).expect("Failed to write custom block");

    // --- READING ---
    let (rem, mut pcapng_parser) = PcapNgParser::new(&buffer).expect("Failed to create parser");
    let mut remaining_data = rem;

    // Read the next block, which should be our custom block
    let (rem, read_block_enum) = pcapng_parser.next_block(remaining_data).expect("Failed to read next block");
    remaining_data = rem;

    // --- VERIFICATION ---
    // Extract the CustomBlock from the enum
    let read_block = match read_block_enum {
        Block::CustomCopiable(block) => block,
        // In a real scenario, you might handle both, but we know we wrote a copiable one.
        _ => panic!("Expected a CustomCopiable block, but got something else."),
    };

    // Assert that the PEN is correct
    assert_eq!(read_block.pen, MyCustomPayload::PEN, "PEN did not match");

    // Parse the payload back to our concrete type
    let read_payload = read_block
        .interpret::<MyCustomPayload>()
        .expect("Failed to parse payload")
        .expect("Payload not recognized");

    // Assert that the inner data is correct
    assert_eq!(read_payload, original_payload, "Payload data did not match");

    // Verify that our custom option in the header was also read correctly.
    match pcapng_parser.section().options.first().expect("No options on section header") {
        SectionHeaderOption::Common(CommonOption::CustomBinaryCopiable(custom)) => {
            let opt_payload = custom
                .interpret::<MyCustomPayload>()
                .expect("Failed to parse payload")
                .expect("Payload not recognized");
            assert_eq!(opt_payload, original_payload, "Option payload data did not match");
        },
        _ => panic!("Expected a custom option"),
    };

    // Verify there is no more data left to parse
    assert!(remaining_data.is_empty(), "Expected all data to be consumed");
}

#[test]
fn parser_handles_section_endianness_switch() {
    use pcap_file::pcapng::blocks::section_header::SectionHeaderOption;

    let data = [
        // Big-endian section header without options.
        0x0A, 0x0D, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x1C, 0x1A, 0x2B, 0x3C, 0x4D, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x1C, // Little-endian section header with an shb_os option of length 8.
        0x0A, 0x0D, 0x0D, 0x0A, 0x2C, 0x00, 0x00, 0x00, 0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x03, 0x00, 0x08, 0x00, b'l', b'i', b'n', b'u', b'x', b'-', b'x', b'6', 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00,
    ];

    let (rem, mut parser) = PcapNgParser::new(&data).unwrap();
    let (rem, block) = parser.next_block(rem).unwrap();

    assert!(rem.is_empty());
    let section = block.as_section_header().unwrap();
    assert_eq!(section.options, vec![SectionHeaderOption::OS("linux-x6".into())]);
}

#[test]
fn writer_handles_section_endianness_switch() {
    use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    use pcap_file::pcapng::blocks::section_header::SectionHeaderBlock;
    use pcap_file::pcapng::blocks::{Block, PcapNgBlock};
    use pcap_file::{DataLink, Endianness};

    let little_section = SectionHeaderBlock { endianness: Endianness::Little, section_length: 128, ..Default::default() };
    let little_interface = InterfaceDescriptionBlock { linktype: DataLink::ETHERNET, snaplen: 64, options: vec![] };
    let big_section = SectionHeaderBlock { endianness: Endianness::Big, section_length: 256, ..Default::default() };
    let big_interface = InterfaceDescriptionBlock { linktype: DataLink::RAW, snaplen: 128, options: vec![] };

    let mut writer = PcapNgWriter::with_section_header(Vec::new(), little_section.clone()).unwrap();
    writer.write_block(&little_interface.clone().into_block()).unwrap();
    writer.write_block(&big_section.clone().into_block()).unwrap();
    writer.write_block(&big_interface.clone().into_block()).unwrap();

    // Check each block value //
    let (rem, mut parser) = PcapNgParser::new(writer.get_ref()).unwrap();
    assert_eq!(parser.section(), &little_section);

    let (rem, block) = parser.next_block(rem).unwrap();
    assert_eq!(block, Block::InterfaceDescription(little_interface));

    let (rem, block) = parser.next_block(rem).unwrap();
    assert_eq!(block, Block::SectionHeader(big_section.clone()));
    assert_eq!(parser.section(), &big_section);

    let (rem, block) = parser.next_block(rem).unwrap();
    assert_eq!(block, Block::InterfaceDescription(big_interface));

    assert!(rem.is_empty());
}

#[test]
fn reader_with_capacity_handles_large_blocks() {
    use std::borrow::Cow;

    use pcap_file::DataLink;
    use pcap_file::pcapng::blocks::PcapNgBlock;
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;

    let data = vec![0xA5; 8_000_001];
    let interface = InterfaceDescriptionBlock::new(DataLink::ETHERNET, data.len() as u32);
    let packet = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: 1_000_000_000,
        original_len: data.len() as u32,
        data: Cow::Borrowed(&data),
        options: vec![],
    };

    let mut writer = PcapNgWriter::with_endianness(Vec::new(), pcap_file::Endianness::Big).unwrap();
    writer.write_block(&interface.into_block()).unwrap();
    writer.write_block(&packet.into_block()).unwrap();
    let pcapng = writer.into_inner();

    let mut reader = PcapNgReader::with_capacity(&pcapng[..], pcapng.len()).unwrap();
    let _ = reader.next_block().unwrap().unwrap();
    let (block, _) = reader.next_block().unwrap().unwrap();
    let packet = block.as_enhanced_packet().unwrap();

    assert_eq!(packet.data.len(), data.len());
    assert_eq!(&*packet.data, data.as_slice());
    assert!(reader.next_block().is_none());
}

#[test]
fn raw_reader_recovers_after_typed_block_validation_error() {
    use byteorder_slice::BigEndian;
    use pcap_file::DataLink;
    use pcap_file::pcapng::blocks::PcapNgBlock;
    use pcap_file::pcapng::blocks::block_common::{ENHANCED_PACKET_BLOCK, RawBlock};
    use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    use pcap_file::pcapng::{ContentValidationError, PcapNgReadError};

    let interface = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0xFFFF);
    let invalid_packet = RawBlock {
        type_: ENHANCED_PACKET_BLOCK,
        initial_len: 32,
        body: vec![
            0x00, 0x00, 0x00, 0x07, // invalid interface_id
            0x00, 0x00, 0x00, 0x00, // timestamp_high
            0x00, 0x00, 0x00, 0x00, // timestamp_low
            0x00, 0x00, 0x00, 0x00, // captured_len
            0x00, 0x00, 0x00, 0x00, // original_len
        ]
        .into(),
        trailer_len: 32,
    };

    let mut writer = PcapNgWriter::with_endianness(Vec::new(), pcap_file::Endianness::Big).unwrap();
    writer.write_block(&interface.into_block()).unwrap();
    invalid_packet.write_to::<BigEndian, _>(writer.get_mut()).unwrap();
    let pcapng = writer.into_inner();

    let mut reader = PcapNgReader::new(&pcapng[..]).unwrap();
    let _ = reader.next_block().unwrap().unwrap();

    let typed_error = reader.next_block().unwrap().unwrap_err();
    match typed_error {
        PcapNgReadError::BlockConversion(error) => {
            assert!(matches!(
                error.source,
                pcap_file::pcapng::BlockContentParseError::Validation(ContentValidationError::InvalidInterfaceId(7))
            ));
        },
        other => panic!("Expected block conversion error, got {other:?}"),
    }

    let (raw_block, _) = reader.next_raw_block().unwrap().unwrap();
    assert_eq!(raw_block.type_, ENHANCED_PACKET_BLOCK);
    assert_eq!(raw_block.body.len(), 20);
    assert!(reader.next_raw_block().is_none());
}

#[test]
fn test_stateful_custom_block() {
    use byteorder_slice::{
        BigEndian, LittleEndian,
        byteorder::{ReadBytesExt, WriteBytesExt},
    };
    use pcap_file::pcapng::PcapNgState;
    use pcap_file::pcapng::blocks::{custom::*, enhanced_packet::*, interface_description::*, opt_common::*, *};
    use pcap_file::{DataLink, Endianness};
    use std::borrow::Cow;
    use std::io::Write;

    // 1. Define a new custom block payload
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MyStatefulPayload {
        magic_number: u64,
        interface_id: u32,
        timestamp: i128,
    }

    // 1.1 Define a new custom error if needed
    #[derive(Debug, thiserror::Error)]
    enum MyCustomPayloadError {
        #[error(transparent)]
        Io(#[from] std::io::Error),

        #[error(transparent)]
        Validation(#[from] ContentValidationError),
    }

    // 2. Implement the required traits for the custom payload
    impl CustomPayloadNonCopiable<'_> for MyStatefulPayload {
        // A unique PEN for our test block
        const PEN: u32 = 70000;

        type State = PcapNgState;
        type WriteToError = MyCustomPayloadError;
        type FromSliceError = MyCustomPayloadError;

        fn write_to<W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<(), MyCustomPayloadError> {
            return match state.section().endianness {
                Endianness::Big => inner::<BigEndian, _>(self, state, writer),
                Endianness::Little => inner::<LittleEndian, _>(self, state, writer),
            };

            fn inner<B: ByteOrder, W: Write>(
                payload: &MyStatefulPayload,
                state: &PcapNgState,
                writer: &mut W,
            ) -> Result<(), MyCustomPayloadError> {
                writer.write_u64::<B>(payload.magic_number)?;
                writer.write_u32::<B>(payload.interface_id)?;
                let (timestamp_high, timestamp_low) = state.encode_timestamp(payload.interface_id, payload.timestamp)?;
                writer.write_u32::<B>(timestamp_high)?;
                writer.write_u32::<B>(timestamp_low)?;

                Ok(())
            }
        }

        fn from_slice(state: &PcapNgState, slice: &[u8]) -> Result<Option<MyStatefulPayload>, MyCustomPayloadError> {
            return match state.section().endianness {
                Endianness::Big => inner::<BigEndian>(state, slice),
                Endianness::Little => inner::<LittleEndian>(state, slice),
            };

            fn inner<B: ByteOrder>(state: &PcapNgState, mut slice: &[u8]) -> Result<Option<MyStatefulPayload>, MyCustomPayloadError> {
                let magic_number = slice.read_u64::<B>()?;
                let interface_id = slice.read_u32::<B>()?;
                let timestamp_high = slice.read_u32::<B>().unwrap();
                let timestamp_low = slice.read_u32::<B>().unwrap();
                let timestamp = state.decode_timestamp(interface_id, timestamp_high, timestamp_low)?;

                Ok(Some(MyStatefulPayload { magic_number, interface_id, timestamp }))
            }
        }
    }

    impl CustomPayloadBlock<'_> for MyStatefulPayload {}
    impl CustomPayloadOption<'_> for MyStatefulPayload {}

    let original_payload = MyStatefulPayload { magic_number: 0xDEADBEEFCAFED00D, interface_id: 0, timestamp: 123456789 };

    let mut buffer = Vec::new();
    let mut pcapng_writer = PcapNgWriter::new(&mut buffer).expect("Failed to create writer");

    // Write an interface description block that sets the timestamp format.
    let interface_description = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 1500,
        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
    };

    pcapng_writer
        .write_block(&interface_description.into_block())
        .expect("Failed to write interface description block");

    let block_to_write = original_payload
        .clone()
        .into_custom_block_non_copiable(pcapng_writer.state())
        .expect("Failed to encode custom block")
        .into_block();

    pcapng_writer.write_block(&block_to_write).expect("Failed to write custom block");

    let packet_block = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: 0,
        original_len: 0,
        data: Cow::Owned(vec![]),
        options: vec![EnhancedPacketOption::Common(
            original_payload
                .clone()
                .into_custom_binary_option_non_copiable(pcapng_writer.state())
                .expect("Failed to encode custom option")
                .into_common_option(),
        )],
    };

    pcapng_writer.write_block(&packet_block.into_block()).expect("Failed to write packet block");

    // --- READING ---
    let mut pcapng_reader = PcapNgReader::new(&buffer[..]).expect("Failed to create reader");

    // Read the first block, which should be the interface description
    let (first_block, _) = pcapng_reader.next_block().expect("No first block from reader").expect("Failed to get first block");

    assert!(matches!(first_block, Block::InterfaceDescription(_)));

    // Read the next block, which should be our custom block
    let (read_block_enum, reader_state) =
        pcapng_reader.next_block().expect("No second block from reader").expect("Failed to get next block");

    // --- VERIFICATION ---
    // Extract the CustomBlock from the enum
    let read_block = match read_block_enum {
        Block::CustomNonCopiable(block) => block,
        _ => panic!("Expected a CustomNonCopiable block, but got something else."),
    };

    // Assert that the PEN is correct
    assert_eq!(read_block.pen, MyStatefulPayload::PEN, "PEN did not match");

    // Parse the payload back to our concrete type
    let read_payload = read_block
        .interpret::<MyStatefulPayload>(reader_state)
        .expect("Failed to parse payload")
        .expect("Payload not recognized");

    // Assert that the inner data is correct
    assert_eq!(read_payload, original_payload, "Payload data did not match");

    // Read the last block, which should be our packet block
    let (last_block, reader_state) = pcapng_reader.next_block().expect("No third block from reader").expect("Failed to get next block");

    match last_block {
        Block::EnhancedPacket(packet) => {
            let option = packet.options.first().expect("No options on packet");
            match option {
                EnhancedPacketOption::Common(CommonOption::CustomBinaryNonCopiable(custom)) => {
                    let opt_payload = custom
                        .interpret::<MyStatefulPayload>(reader_state)
                        .expect("Failed to parse payload")
                        .expect("Payload not recognized");
                    assert_eq!(opt_payload, original_payload, "Option payload data did not match");
                },
                _ => panic!("Expected a custom option"),
            }
        },
        _ => panic!("Expected an enhanced packet block"),
    };

    // Verify there is no more data left to parse
    let remaining_data = pcapng_reader.into_inner();
    assert!(remaining_data.is_empty(), "Expected all data to be consumed");
}
