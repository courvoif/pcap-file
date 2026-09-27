//! Reads packets from an existing pcapng test capture through the packet iterator.

/* ----- Imports ----- */

use std::fs::File;

use pcap_file::pcapng::PcapNgReader;

/* ----- Main ----- */

/// Iterates over packets and prints the captured length of each one.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcapng/little_endian/basic/test001.pcapng")?;
    let reader = PcapNgReader::new(file, true)?;

    for result in reader.packets() {
        match result {
            Ok(packet) => println!("{} bytes", packet.data.len()),
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
