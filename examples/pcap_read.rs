use std::fs::File;

use anyhow::{Context, Result};
use pcap_file::pcap::PcapReader;

fn main() -> Result<()> {
    let input = File::open("tests/pcap/little_endian.pcap").context("failed to open the pcap test capture")?;
    let reader = PcapReader::new(input).context("failed to read the pcap header")?;
    let mut packets = reader.into_iter();

    for packet in packets.by_ref() {
        let packet = packet.context("failed to read a pcap packet")?;
        println!("{} bytes at {:?}", packet.len(), packet.timestamp());
    }

    // packets.by_ref() keeps the iterator available, and get_ref() provides access to
    // the original reader and its global header.
    println!("link type: {:?}", packets.get_ref().header().datalink);

    Ok(())
}
