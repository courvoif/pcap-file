//! Writes a generated packet to an in-memory classic pcap capture.

/* ----- Imports ----- */

use std::time::Duration;

use pcap_file::pcap::{PcapPacket, PcapWriter};

/* ----- Main ----- */

/// Writes one generated packet and reports the serialized capture size.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // These bytes are just example packet data.
    let data = [0_u8; 64];
    let packet = PcapPacket::new(Duration::from_secs(1), data.len() as u32, &data[..])?;
    let mut writer = PcapWriter::new(Vec::new())?;

    writer.write_packet(&packet)?;
    let capture = writer.into_inner();
    println!("wrote {} bytes", capture.len());

    Ok(())
}
