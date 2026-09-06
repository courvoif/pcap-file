use std::borrow::Cow;
use std::io::Cursor;

use anyhow::{Context, Result};
use pcap_file::pcap::{PcapReader, PcapWriter, RawPcapPacket};

fn main() -> Result<()> {
    let data = malformed_pcap().context("failed to build the malformed pcap")?;
    let mut reader = PcapReader::new(Cursor::new(data)).context("failed to read the pcap header")?;
    let header = reader.header();

    while let Some(packet) = reader.next_raw_packet() {
        let raw_packet = packet.context("failed to read a raw packet")?;

        match raw_packet.try_into_pcap_packet(header.ts_resolution, header.snaplen) {
            Ok(packet) => println!("valid packet: {} bytes", packet.len()),
            Err(error) => {
                // Reading raw packets from the beginning lets an application
                // handle malformed typed content.
                eprintln!("invalid packet: {error}");
                println!("handled raw packet: {} bytes", error.packet.data.len());
            }
        }
    }

    Ok(())
}

fn malformed_pcap() -> Result<Vec<u8>> {
    let packet = RawPcapPacket {
        ts_sec: 1,
        ts_frac: 0,
        incl_len: 4,
        // Invalid because the captured data is longer than the original packet.
        orig_len: 2,
        data: Cow::Borrowed(&[1, 2, 3, 4]),
    };

    let mut writer = PcapWriter::new(Vec::new()).context("failed to write the generated pcap header")?;

    writer
        .write_raw_packet(&packet)
        .context("failed to write the generated raw packet")?;

    Ok(writer.into_inner())
}
