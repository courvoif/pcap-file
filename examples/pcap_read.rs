use std::error::Error;
use std::fs::File;

use pcap_file::pcap::PcapReader;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "capture.pcap".into());
    let mut reader = PcapReader::new(File::open(path)?)?;

    println!("link type: {:?}", reader.header().datalink);
    while let Some(packet) = reader.next_packet() {
        let packet = packet?;
        println!("{} bytes at {:?}", packet.len(), packet.timestamp());
    }

    Ok(())
}
