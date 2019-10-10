use pcap_file::pcapng::PcapngReader;

#[test]
fn test() {

    let data  = include_bytes!("big_endian/advanced/test101.pcapng");

    //Global header test
    let mut pcapng_reader = PcapngReader::new(&data[..]).unwrap();
    println!("{:?}", pcapng_reader.section());
    for block in pcapng_reader {
        let block = block.unwrap();
        println!("{:?}", block.parsed());
    }
}