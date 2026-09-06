use std::fs::File;

use anyhow::{Context, Result};
use pcap_file::pcapng::PcapNgReader;

fn main() -> Result<()> {
    let input =
        File::open("tests/test_multiple_interfaces.pcapng").context("failed to open the pcapng test capture")?;
    let reader = PcapNgReader::new(input).context("failed to read the pcapng section header")?;

    // The iterator is the simplest API when processing packets does not require
    // pcapng state. It skips non-packet blocks, returns owned packets, and stops
    // after the first error.
    // Use PcapNgReader::next_block() when the state is needed for each block,
    // or next_raw_block() when malformed block content must be handled.
    for packet in reader {
        let packet = packet.context("failed to read a pcapng packet")?;
        println!("{} captured bytes", packet.data().len());
    }

    Ok(())
}
