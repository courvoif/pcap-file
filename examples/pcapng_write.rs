use std::fs::File;
use std::io::BufWriter;
use std::time::Duration;

use anyhow::{Context, Result};
use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;

fn main() -> Result<()> {
    let output = File::create("target/pcapng-write-example.pcapng").context("failed to create the output pcapng")?;
    let mut writer = PcapNgWriter::new(BufWriter::new(output)).context("failed to write the pcapng section header")?;

    // Interface IDs are zero-based in the order Interface Description Blocks
    // are written. Therefore this interface has ID 0.
    writer
        .write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535))
        .context("failed to write the interface description")?;

    let data = [0_u8; 60];
    writer
        .write_pcapng_block(EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_secs(1_700_000_000),
            original_len: data.len() as u32,
            data: data.as_slice().into(),
            options: vec![],
        })
        .context("failed to write the enhanced packet")?;

    Ok(())
}
