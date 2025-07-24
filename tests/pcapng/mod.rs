use std::fs::File;
use std::io::Read;

use glob::glob;
use pcap_file::pcapng::{PcapNgParser, PcapNgReader, PcapNgWriter};

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
            let block = block.unwrap();
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
                let expected = expected.unwrap();
                let actual = actual.unwrap();

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
    use pcap_file::pcapng::blocks::{
        custom::*,
        section_header::*,
        opt_common::*,
        *
    };
    use std::io::{Error as IoError, Write};

    // 1. Define a new custom block payload
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MyCustomPayload {
        magic_number: u64,
    }

    // 2. Implement the required traits for the custom payload
    impl CustomCopiable<'_> for MyCustomPayload {

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

    let original_payload = MyCustomPayload { magic_number: 0xDEADBEEFCAFED00D };

    let section = SectionHeaderBlock {
        options: vec![
            SectionHeaderOption::Common(
                original_payload
                    .clone()
                    .into_custom_option()
                    .expect("Failed to encode custom option")
                    .into_common_option()
            ),
        ],
        .. Default::default()
    };

    let mut buffer = Vec::new();
    let mut pcapng_writer = PcapNgWriter::with_section_header(&mut buffer, section)
        .expect("Failed to create writer");

    let block_to_write = original_payload
        .clone()
        .into_custom_block()
        .expect("Failed to encode custom block")
        .into_block();

    pcapng_writer
        .write_block(&block_to_write)
        .expect("Failed to write custom block");

    // --- READING ---
    let (rem, mut pcapng_parser) = PcapNgParser::new(&buffer)
        .expect("Failed to create parser");
    let mut remaining_data = rem;

    // Read the next block, which should be our custom block
    let (rem, read_block_enum) = pcapng_parser
        .next_block(remaining_data)
        .expect("Failed to read next block");
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
    match pcapng_parser
        .section()
        .options
        .first()
        .expect("No options on section header")
    {
        SectionHeaderOption::Common(
            CommonOption::CustomBinaryCopiable(custom)) => {
                let opt_payload = custom
                    .interpret::<MyCustomPayload>()
                    .expect("Failed to parse payload")
                    .expect("Payload not recognized");
                assert_eq!(opt_payload, original_payload,
                           "Option payload data did not match");
        }
        _ => panic!("Expected a custom option")
    };

    // Verify there is no more data left to parse
    assert!(remaining_data.is_empty(), "Expected all data to be consumed");
}

#[test]
fn test_stateful_custom_block() {
    use byteorder_slice::{
        BigEndian, LittleEndian,
        byteorder::{ReadBytesExt, WriteBytesExt},
    };
    use pcap_file::{PcapError, Endianness, DataLink};
    use pcap_file::pcapng::PcapNgState;
    use pcap_file::pcapng::blocks::{
        custom::*,
        enhanced_packet::*,
        interface_description::*,
        opt_common::*,
        *
    };
    use std::borrow::Cow;
    use std::io::Write;
    use std::time::Duration;

    // 1. Define a new custom block payload
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MyStatefulPayload {
        magic_number: u64,
        interface_id: u32,
        timestamp: Duration,
    }

    // 2. Implement the required traits for the custom payload
    impl CustomNonCopiable<'_> for MyStatefulPayload {

        // A unique PEN for our test block
        const PEN: u32 = 70000;

        type State = PcapNgState;
        type WriteToError = PcapError;
        type FromSliceError = PcapError;

        fn write_to<W: Write>(
            &self,
            state: &PcapNgState,
            writer: &mut W,
        ) -> Result<(), PcapError> {
            match state.section().endianness {
                Endianness::Big => {
                    writer.write_u64::<BigEndian>(self.magic_number)?;
                    writer.write_u32::<BigEndian>(self.interface_id)?;
                    state.encode_timestamp::<BigEndian, W>(
                        self.interface_id, self.timestamp, writer)?;
                },
                Endianness::Little => {
                    writer.write_u64::<LittleEndian>(self.magic_number)?;
                    writer.write_u32::<LittleEndian>(self.interface_id)?;
                    state.encode_timestamp::<LittleEndian, W>(
                        self.interface_id, self.timestamp, writer)?;
                },
            };
            Ok(())
        }

        fn from_slice(
            state: &PcapNgState,
            mut slice: &[u8],
        ) -> Result<Option<MyStatefulPayload>, PcapError> {
            Ok(Some(match state.section().endianness {
                Endianness::Big => {
                    let magic_number = slice.read_u64::<BigEndian>()?;
                    let interface_id = slice.read_u32::<BigEndian>()?;
                    let timestamp = state.decode_timestamp::<BigEndian>(
                        interface_id, &mut slice)?;
                    MyStatefulPayload { magic_number, interface_id, timestamp }
                },
                Endianness::Little => {
                    let magic_number = slice.read_u64::<LittleEndian>()?;
                    let interface_id = slice.read_u32::<LittleEndian>()?;
                    let timestamp = state.decode_timestamp::<LittleEndian>(
                        interface_id, &mut slice)?;
                    MyStatefulPayload { magic_number, interface_id, timestamp }
                },
            }))
        }
    }

    let original_payload = MyStatefulPayload {
        magic_number: 0xDEADBEEFCAFED00D,
        interface_id: 0,
        timestamp: Duration::from_nanos(123456789),
    };

    let mut buffer = Vec::new();
    let mut pcapng_writer = PcapNgWriter::new(&mut buffer)
        .expect("Failed to create writer");

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
        .into_custom_block(pcapng_writer.state())
        .expect("Failed to encode custom block")
        .into_block();

    pcapng_writer
        .write_block(&block_to_write)
        .expect("Failed to write custom block");

    let packet_block = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: Duration::ZERO,
        original_len: 0,
        data: Cow::Owned(vec![]),
        options: vec![
            EnhancedPacketOption::Common(
                original_payload
                    .clone()
                    .into_custom_option(pcapng_writer.state())
                    .expect("Failed to encode custom option")
                    .into_common_option()
            ),
        ]
    };

    pcapng_writer
        .write_block(&packet_block.into_block())
        .expect("Failed to write packet block");

    // --- READING ---
    let mut pcapng_reader = PcapNgReader::new(&buffer[..])
        .expect("Failed to create reader");

    // Read the first block, which should be the interface description
    let first_block = pcapng_reader
        .next_block()
        .expect("No first block from reader")
        .expect("Failed to get first block");

    assert!(matches!(first_block, Block::InterfaceDescription(_)));

    // Read the next block, which should be our custom block
    let (read_block_enum, reader_state) = pcapng_reader
        .next_block_and_state()
        .expect("No second block from reader")
        .expect("Failed to get next block");

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
    let (last_block, reader_state) = pcapng_reader
        .next_block_and_state()
        .expect("No third block from reader")
        .expect("Failed to get next block");

    match last_block {
        Block::EnhancedPacket(packet) => {
            let option = packet.options
                .first()
                .expect("No options on packet");
            match option {
                EnhancedPacketOption::Common(
                    CommonOption::CustomBinaryNonCopiable(custom)) => {
                        let opt_payload = custom
                            .interpret::<MyStatefulPayload>(reader_state)
                            .expect("Failed to parse payload")
                            .expect("Payload not recognized");
                        assert_eq!(opt_payload, original_payload,
                                   "Option payload data did not match");
                }
                _ => panic!("Expected a custom option")
            }
        },
        _ => panic!("Expected an enhanced packet block")
    };

    // Verify there is no more data left to parse
    let remaining_data = pcapng_reader.into_inner();
    assert!(remaining_data.is_empty(), "Expected all data to be consumed");
}
