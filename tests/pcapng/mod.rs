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
