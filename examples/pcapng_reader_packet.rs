//! Reads borrowed packets from an existing pcapng test capture.

/* ----- Imports ----- */

use std::fs::File;

use pcap_file::pcapng::PcapNgReader;

/* ----- Main ----- */

/// Reads and prints packet lengths without copying the captured bytes.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcapng/little_endian/basic/test001.pcapng")?;
    let mut reader = PcapNgReader::new(file, true)?;

    // Finish using each borrowed packet before reading the next one.
    while let Some(result) = reader.next_packet() {
        match result {
            Ok(packet) => println!("{} bytes", packet.data.len()),
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
