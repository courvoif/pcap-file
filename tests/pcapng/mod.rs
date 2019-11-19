use pcap_file::pcapng::PcapNgReader;
use std::fs::File;
use glob::glob;

#[test]
fn test() {

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