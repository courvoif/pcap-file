use anyhow::{Context, Result};
use pcap_file::pcapng::{Block, PcapNgParser};

fn main() -> Result<()> {
    let data = std::fs::read("tests/pcapng/little_endian/basic/test001.pcapng")
        .context("failed to read the pcapng test capture")?;

    // new() consumes and validates the first Section Header Block.
    let (mut remaining, mut parser) = PcapNgParser::new(&data).context("failed to parse the pcapng section header")?;
    println!("section endianness: {:?}", parser.state().endianness());

    while !remaining.is_empty() {
        let (next, block) = parser.next_block(remaining).context("failed to parse a pcapng block")?;

        if let Block::EnhancedPacket(packet) = block {
            let interface = parser
                .packet_interface(&packet)
                .context("packet refers to an unknown interface")?;

            println!("{} bytes on {:?}", packet.data.len(), interface.linktype);
        }

        remaining = next;
    }

    Ok(())
}
