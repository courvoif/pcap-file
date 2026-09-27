//! Parses packet records from the existing classic pcap test capture.

/* ----- Imports ----- */

use pcap_file::pcap::{PcapParseError, PcapParser};

/* ----- Main ----- */

/// Parses and prints the captured length of each packet in the fixture.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capture = std::fs::read("tests/pcap/little_endian.pcap")?;
    // The parser reads the global header and returns the remaining packet bytes.
    let (mut remaining, parser) = PcapParser::new(&capture)?;

    while !remaining.is_empty() {
        match parser.next_packet(remaining) {
            Ok((rest, packet)) => {
                println!("{} bytes", packet.len());
                remaining = rest;
            }
            Err(PcapParseError::Validation(error)) => {
                eprintln!("skipping invalid packet: {error}");
                // The raw parser can advance past a packet that failed validation.
                let (rest, _) = parser.next_raw_packet(remaining)?;
                remaining = rest;
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
