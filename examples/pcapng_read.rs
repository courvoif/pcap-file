use std::fs::File;

use anyhow::{Context, Result};
use pcap_file::pcapng::{Block, PcapNgReader};

fn main() -> Result<()> {
    let input =
        File::open("tests/test_multiple_interfaces.pcapng").context("failed to open the pcapng test capture")?;
    let reader = PcapNgReader::new(input).context("failed to read the pcapng section header")?;

    // The iterator is the simplest API when processing blocks does not require
    // pcapng state. It returns owned blocks and stops after the first error.
    // Use PcapNgReader::next_block() when the state is needed for each block or
    // when typed errors may need recovery through next_raw_block().
    for block in reader {
        let block = block.context("failed to read a pcapng block")?;
        if let Block::EnhancedPacket(packet) = block {
            println!("{} bytes on interface {}", packet.data.len(), packet.interface_id);
        }
    }

    Ok(())
}
