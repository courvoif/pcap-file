//! Reads raw packet fields from the existing classic pcap test capture.

/* ----- Imports ----- */

use std::fs::File;

use pcap_file::pcap::PcapReader;

/* ----- Main ----- */

/// Prints raw packet fields and checks whether each packet is valid.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcap/little_endian.pcap")?;
    let mut reader = PcapReader::new(file)?;
    let header = reader.header();

    while let Some(result) = reader.next_raw_packet() {
        match result {
            Ok(raw_packet) => {
                println!(
                    "timestamp: {}.{}, captured: {} bytes, original: {} bytes",
                    raw_packet.ts_sec, raw_packet.ts_frac, raw_packet.incl_len, raw_packet.orig_len
                );

                // Raw packets keep their fields even when semantic validation fails.
                if let Err(error) = raw_packet.try_into_pcap_packet(header.ts_resolution, header.snaplen) {
                    eprintln!("invalid packet: {error}");
                }
            }
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
