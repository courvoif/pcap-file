//! Writes generated blocks to an in-memory pcapng capture.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::time::Duration;

use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;

/* ----- Main ----- */

/// Writes an interface block and one generated packet block.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), true)?;

    // Packet blocks use an interface by index; this packet uses interface 0.
    writer.write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535))?;

    // These bytes are just example packet data.
    let data = [0_u8; 64];
    let packet = EnhancedPacketBlock {
        timestamp: Duration::from_secs(1),
        original_len: data.len() as u32,
        data: Cow::Borrowed(&data),
        ..Default::default()
    };
    writer.write_pcapng_block(packet)?;

    let capture = writer.into_inner();
    println!("wrote {} bytes", capture.len());

    Ok(())
}
