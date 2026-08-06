use anyhow::{Context, Result};
use pcap_file::pcap::PcapParser;

fn main() -> Result<()> {
    let data = std::fs::read("tests/pcap/big_endian.pcap").context("failed to read the pcap")?;

    // PcapParser works directly on a byte slice and does no I/O.
    let (mut remaining, parser) = PcapParser::new(&data).context("failed to parse the pcap header")?;

    while !remaining.is_empty() {
        let (next, packet) = parser.next_packet(remaining).context("failed to parse a pcap packet")?;
        println!("{} bytes at {:?}", packet.len(), packet.timestamp());
        remaining = next;
    }

    Ok(())
}
