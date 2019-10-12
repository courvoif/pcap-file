use pcap_file::pcapng::PcapNgReader;
use std::fs::File;
use glob::glob;

#[test]
fn test() {

    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();
        //println!("Testing: {:?}", entry);

        let mut file = File::open(entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(file).unwrap();

        //println!("{:?}", pcapng_reader.section());
        for block in pcapng_reader {
            let block = block.unwrap();
            //println!("{:?}", block.parsed());
        }

        //println!("\n\n");
    }
}

/*
#[test]
fn test_one() {

    let mut file = File::open("tests/pcapng/big_endian/basic/test008.pcapng").unwrap();
    let mut pcapng_reader = PcapngReader::new(file).unwrap();

    println!("{:?}", pcapng_reader.section());
    for block in pcapng_reader {
        let block = block.unwrap();
        println!("{:?}", block.parsed());
    }
}*/