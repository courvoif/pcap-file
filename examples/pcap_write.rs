use std::error::Error;
use std::fs::File;
use std::time::Duration;

use pcap_file::DataLink;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "output.pcap".into());
    let header = PcapHeader {
        datalink: DataLink::ETHERNET,
        snaplen: 65_535,
        ..Default::default()
    };
    let mut writer = PcapWriter::with_header(File::create(path)?, header)?;

    // This is a minimal Ethernet frame payload for demonstration purposes.
    let data = [0_u8; 60];
    let packet = PcapPacket::new(Duration::from_secs(1_700_000_000), data.len() as u32, data.as_slice())?;
    writer.write_packet(&packet)?;
    writer.flush()?;

    Ok(())
}
