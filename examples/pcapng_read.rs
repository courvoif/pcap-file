use std::fs::File;

use anyhow::{Context, Result};
use pcap_file::pcapng::{Block, PcapNgReader};

fn main() -> Result<()> {
    let input =
        File::open("tests/test_multiple_interfaces.pcapng").context("failed to open the pcapng test capture")?;
    let reader = PcapNgReader::new(input).context("failed to read the pcapng section header")?;

    for block in reader {
        let block = block.context("failed to read a pcapng block")?;
        if let Block::EnhancedPacket(packet) = block {
            println!("{} bytes on interface {}", packet.data.len(), packet.interface_id);
        }
    }

    Ok(())
}
