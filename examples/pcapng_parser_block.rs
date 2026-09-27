//! Parses blocks from an existing pcapng test capture.

/* ----- Imports ----- */

use pcap_file::pcapng::PcapNgParser;
use pcap_file::pcapng::errors::PcapNgParseError;

/* ----- Main ----- */

/// Parses and prints the type of each block in the fixture.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capture = std::fs::read("tests/pcapng/little_endian/basic/test001.pcapng")?;
    // The parser reads the section header and returns the remaining block bytes.
    let (mut remaining, mut parser) = PcapNgParser::new(&capture, true)?;

    while !remaining.is_empty() {
        match parser.next_block(remaining) {
            Ok((rest, block)) => {
                println!("block type: {:#010x}", block.type_code());
                remaining = rest;
            }
            Err(error @ PcapNgParseError::Block(_)) => {
                eprintln!("skipping undecodable block: {error}");
                // Its framing is valid, so the raw parser can move to the next block.
                let (rest, _) = parser.next_raw_block(remaining)?;
                remaining = rest;
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
