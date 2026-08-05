use std::error::Error;

use pcap_file::pcap::PcapParser;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "capture.pcap".into());
    let data = std::fs::read(path)?;

    // PcapParser works directly on a byte slice and does no I/O.
    let (mut remaining, parser) = PcapParser::new(&data)?;
    while !remaining.is_empty() {
        let (next, packet) = parser.next_packet(remaining)?;
        println!("{} bytes at {:?}", packet.len(), packet.timestamp());
        remaining = next;
    }

    Ok(())
}
