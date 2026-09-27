//! Reads packet records from the existing classic pcap test capture.

/* ----- Imports ----- */

use std::fs::File;

use pcap_file::pcap::PcapReader;

/* ----- Main ----- */

/// Reads and prints the captured length of each packet in the fixture.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcap/little_endian.pcap")?;
    let mut reader = PcapReader::new(file)?;

    while let Some(result) = reader.next_packet() {
        match result {
            Ok(packet) => println!("{} bytes", packet.len()),
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
