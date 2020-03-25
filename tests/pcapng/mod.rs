use pcap_file::pcapng::{PcapNgReader, PcapNgParser, PcapNgWriter, ParsedBlock, Block};
use std::fs::File;
use glob::glob;
use std::io::Read;

#[test]
fn reader() {

    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let file = File::open(&entry).unwrap();
        let pcapng_reader = PcapNgReader::new(file).unwrap();

        for (i, block) in pcapng_reader.enumerate() {
            let _block = block.expect(&format!("Error on block {} on file: {:?}", i, entry));
            let _parsed = _block.parsed().expect(&format!("Error on parsed block {} file: {:?}", i, entry));
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

            let (rem, block) =  pcapng_parser.next_block(src).expect(&format!("Error on block {} on file: {:?}", i, entry));
            block.parsed().expect(&format!("Error on parsed block {} on file: {:?}", i, entry));
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
        let pcapng_reader = PcapNgReader::new(&pcapng_in[..]).unwrap();

        let mut pcapng_writer = PcapNgWriter::with_section_header( Vec::new(), pcapng_reader.section()).unwrap();

        for (i, block) in pcapng_reader.enumerate() {

            let _block = block.unwrap();
            let parsed = _block.parsed().unwrap();
            pcapng_writer.write_block(&parsed).expect(&format!("Error writing parsed block n°{} in file: {:?}, {:?}", i, entry, parsed));
        }


        let expecteds = PcapNgReader::new(&pcapng_in[..]).unwrap();
        let actuals =  PcapNgReader::new(&pcapng_writer.get_ref()[..]).expect(&format!("Error reading section header block in file: {:?}\n expected {:?}\n actual   {:?}", entry, &pcapng_in[..], &pcapng_writer.get_ref()[..]));

        for (i, (actual, expected)) in actuals.zip(expecteds).enumerate() {

            let actual_block = actual.expect(&format!("Error on block {} on file: {:?}", i, entry));
            let expected_block = expected.unwrap();

            let actual_parsed = actual_block.parsed().expect(&format!("Error on parsed block {} on file: {:?}\nActual:   {:02X?}\nExpected: {:02X?}", i, entry, actual_block, expected_block));
            let expected_parsed = expected_block.parsed().unwrap();

            if actual_parsed != expected_parsed {
                assert_eq!(actual_parsed, expected_parsed)
            }
        }
    }
}