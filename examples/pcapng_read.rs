use std::error::Error;
use std::fs::File;

use pcap_file::pcapng::{Block, PcapNgReader};

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "capture.pcapng".into());
    let mut reader = PcapNgReader::new(File::open(path)?)?;

    while let Some(result) = reader.next_block() {
        // The returned state already includes the effects of this block.
        let (block, state) = result?;
        if let Block::EnhancedPacket(packet) = block {
            let interface = state
                .interfaces()
                .get(packet.interface_id as usize)
                .ok_or("packet refers to an unknown interface")?;
            println!("{} bytes on {:?}", packet.data.len(), interface.linktype);
        }
    }

    Ok(())
}
