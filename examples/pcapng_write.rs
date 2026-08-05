use std::error::Error;
use std::fs::File;
use std::time::Duration;

use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "output.pcapng".into());
    let mut writer = PcapNgWriter::new(File::create(path)?)?;

    // Interface IDs are zero-based in the order Interface Description Blocks
    // are written. Therefore this interface has ID 0.
    writer.write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535))?;

    let data = [0_u8; 60];
    writer.write_pcapng_block(EnhancedPacketBlock {
        interface_id: 0,
        timestamp: Duration::from_secs(1_700_000_000),
        original_len: data.len() as u32,
        data: data.as_slice().into(),
        options: vec![],
    })?;

    Ok(())
}
