use std::fs::File;

use anyhow::{Context, Result};
use pcap_file::pcap::PcapReader;

fn main() -> Result<()> {
    let input = File::open("tests/pcap/little_endian.pcap").context("failed to open the pcap test capture")?;
    let reader = PcapReader::new(input).context("failed to read the pcap header")?;

    println!("link type: {:?}", reader.header().datalink);

    for packet in reader {
        let packet = packet.context("failed to read a pcap packet")?;
        println!("{} bytes at {:?}", packet.len(), packet.timestamp());
    }

    Ok(())
}
