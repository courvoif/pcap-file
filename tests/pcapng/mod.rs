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
    use pcap_file::PcapError;
    use pcap_file::pcapng::blocks::{custom::*, *};
    use std::io::Write;

    // 1. Define a new custom block payload
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MyCustomPayload {
        magic_number: u64,
    }

    // 2. Implement the required traits for the custom payload
    impl CustomCopiable<'_> for MyCustomPayload {

        // A unique PEN for our test block
        const PEN: u32 = 70000;

        fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), PcapError> {
            writer.write_u64::<BigEndian>(self.magic_number)?;
            Ok(())
        }

        fn from_slice(slice: &[u8]) -> Result<Option<MyCustomPayload>, PcapError> {
            let mut cursor = std::io::Cursor::new(slice);
            let magic_number = cursor.read_u64::<BigEndian>()?;
            Ok(Some(MyCustomPayload { magic_number }))
        }
    }

    let original_payload = MyCustomPayload { magic_number: 0xDEADBEEFCAFED00D };

    let mut buffer = Vec::new();
    let mut pcapng_writer = PcapNgWriter::new(&mut buffer)
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

    // Verify there is no more data left to parse
    assert!(remaining_data.is_empty(), "Expected all data to be consumed");
}
