use std::fs::File;
use std::io::BufWriter;
use std::time::Duration;

use anyhow::{Context, Result};
use pcap_file::DataLink;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

fn main() -> Result<()> {
    let header = PcapHeader {
        datalink: DataLink::ETHERNET,
        snaplen: 65_535,
        ..Default::default()
    };

    let output = File::create("target/pcap-write-example.pcap").context("failed to create the output pcap")?;
    let mut writer =
        PcapWriter::with_header(BufWriter::new(output), header).context("failed to write the pcap header")?;

    // This is a minimal Ethernet frame payload for demonstration purposes.
    let data = [0_u8; 60];
    let packet = PcapPacket::new(Duration::from_secs(1_700_000_000), data.len() as u32, data.as_slice())
        .context("failed to create the pcap packet")?;

    writer
        .write_packet(&packet)
        .context("failed to write the pcap packet")?;

    Ok(())
}
