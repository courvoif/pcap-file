//! Reads the pcap test capture through the owned packet iterator.

/* ----- Imports ----- */

use std::fs::File;

use pcap_file::pcap::PcapReader;

/* ----- Main ----- */

/// Iterates over and prints the captured length of each packet in the fixture.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcap/little_endian.pcap")?;
    let reader = PcapReader::new(file)?;

    for result in reader.packets() {
        match result {
            Ok(packet) => println!("{} bytes", packet.len()),
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
