use std::error::Error;

use pcap_file::pcapng::{Block, PcapNgParser};

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "capture.pcapng".into());
    let data = std::fs::read(path)?;

    // new() consumes and validates the first Section Header Block.
    let (mut remaining, mut parser) = PcapNgParser::new(&data)?;
    println!("section endianness: {:?}", parser.state().endianness());

    while !remaining.is_empty() {
        let (next, block) = parser.next_block(remaining)?;
        if let Block::EnhancedPacket(packet) = block {
            let interface = parser
                .packet_interface(&packet)
                .ok_or("packet refers to an unknown interface")?;
            println!("{} bytes on {:?}", packet.data.len(), interface.linktype);
        }
        remaining = next;
    }

    Ok(())
}
