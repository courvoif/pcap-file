use std::borrow::Cow;
use std::io::Cursor;

use anyhow::{Context, Result};
use pcap_file::pcap::{PcapReadError, PcapReader, PcapWriter, RawPcapPacket};

fn main() -> Result<()> {
    let data = malformed_pcap().context("failed to build the malformed pcap")?;
    let mut reader = PcapReader::new(Cursor::new(data)).context("failed to read the pcap header")?;

    loop {
        match reader.next_packet() {
            Some(Ok(packet)) => println!("valid packet: {} bytes", packet.len()),
            Some(Err(PcapReadError::Validation(error))) => {
                // A typed validation error does not advance the reader. Reading the
                // same packet in raw form lets an application inspect or preserve it.
                eprintln!("invalid packet: {error}");

                let raw = reader
                    .next_raw_packet()
                    .context("typed error was not followed by a raw packet")?
                    .context("failed to read the malformed packet as raw data")?;

                println!("recovered raw packet: {} bytes", raw.data.len());
            }
            Some(Err(error)) => return Err(error.into()),
            None => break,
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
