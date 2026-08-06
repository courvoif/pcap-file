use std::borrow::Cow;
use std::io::Cursor;

use anyhow::{Context, Result};
use byteorder_slice::BigEndian;
use pcap_file::DataLink;
use pcap_file::pcapng::blocks::block_common::{ENHANCED_PACKET_BLOCK, RawBlock};
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::{PcapNgReadError, PcapNgReader, PcapNgWriter};

fn main() -> Result<()> {
    let data = malformed_pcapng().context("failed to build the malformed pcapng")?;
    let mut reader = PcapNgReader::new(Cursor::new(data)).context("failed to read the pcapng section header")?;

    loop {
        match reader.next_block() {
            Some(Ok((block, _state))) => println!("valid block: {block:?}"),
            Some(Err(PcapNgReadError::BlockConversion(error))) => {
                // A non-state block that fails typed conversion does not advance the
                // reader. Reading it raw lets an application inspect or preserve it.
                eprintln!("invalid block: {error}");

                let (raw, _state) = reader
                    .next_raw_block()
                    .context("typed error was not followed by a raw block")?
                    .context("failed to read the malformed block as raw data")?;

                println!("recovered raw block type: {:#x}", raw.type_);
            }
            Some(Err(error)) => return Err(error.into()),
            None => break,
        }
    }

    Ok(())
}

fn malformed_pcapng() -> Result<Vec<u8>> {
    let interface = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535);
    let invalid_packet = RawBlock {
        type_: ENHANCED_PACKET_BLOCK,
        initial_len: 32,
        body: Cow::Borrowed(&[
            0, 0, 0, 7, // Invalid interface ID: only interface 0 exists.
            0, 0, 0, 0, // Timestamp high.
            0, 0, 0, 0, // Timestamp low.
            0, 0, 0, 0, // Captured length.
            0, 0, 0, 0, // Original length.
        ]),
        trailer_len: 32,
    };

    let mut writer = PcapNgWriter::with_endianness(Vec::new(), pcap_file::Endianness::Big)
        .context("failed to write the generated pcapng section header")?;

    writer
        .write_pcapng_block(interface)
        .context("failed to write the generated interface description")?;

    invalid_packet
        .write_to::<BigEndian, _>(writer.get_mut())
        .context("failed to write the generated raw block")?;

    Ok(writer.into_inner())
}
