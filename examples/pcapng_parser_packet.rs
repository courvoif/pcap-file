//! Parses borrowed packets from a pcapng byte slice.

/* ----- Imports ----- */

use pcap_file::pcapng::PcapNgParser;

/* ----- Main ----- */

/// Parses and prints packet lengths, stopping on the first invalid block.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capture = std::fs::read("tests/pcapng/little_endian/basic/test001.pcapng")?;
    let (mut remaining, mut parser) = PcapNgParser::new(&capture, true)?;

    while !remaining.is_empty() {
        let (rest, packet) = parser.next_packet(remaining)?;
        remaining = rest;
        if let Some(packet) = packet {
            println!("{} bytes", packet.data.len());
        }
    }

    Ok(())
}
