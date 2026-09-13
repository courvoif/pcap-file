use std::borrow::Cow;
use std::io::Cursor;

use anyhow::{Context, Result};
use byteorder_slice::BigEndian;
use pcap_file::DataLink;
use pcap_file::pcapng::blocks::block_common::ENHANCED_PACKET_BLOCK;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::{PcapNgReader, PcapNgWriter, RawBlock};

fn main() -> Result<()> {
    let data = malformed_pcapng().context("failed to build the malformed pcapng")?;
    let mut reader = PcapNgReader::new(Cursor::new(data)).context("failed to read the pcapng section header")?;

    while let Some(block_res) = reader.next_raw_block() {
        let (raw_block, state) = block_res.context("failed to read a raw block")?;

        match raw_block.try_into_block(state) {
            Ok(block) => println!("valid block: {block:?}"),
            Err(error) => {
                // Raw reading has already consumed the structurally valid block,
                // so malformed typed content can be inspected without retrying.
                eprintln!("invalid block: {error}");
                println!("handled raw block type: {:#x}", error.block.type_);
            }
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
        .write_typed_block(interface)
        .context("failed to write the generated interface description")?;

    invalid_packet
        .write_to::<BigEndian, _>(writer.get_mut())
        .context("failed to write the generated raw block")?;

    Ok(writer.into_inner())
}
