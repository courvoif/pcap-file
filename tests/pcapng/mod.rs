use pcap_file::pcapng::{PcapNgReader, PcapNgParser};
use std::fs::File;
use glob::glob;
use std::io::Read;
use pcap_file::PcapError;

#[test]
fn reader() {

    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let file = File::open(&entry).unwrap();
        let pcapng_reader = PcapNgReader::new(file).unwrap();

        for (i, block) in pcapng_reader.enumerate() {
            let _block = block.expect(&format!("Error on block {} on file: {:?}", i, entry));
            let parsed = _block.parsed().expect(&format!("Error on parsed block {} file: {:?}", i, entry));
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