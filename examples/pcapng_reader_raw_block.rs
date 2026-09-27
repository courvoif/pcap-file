//! Reads raw blocks from the existing pcapng test capture.

/* ----- Imports ----- */

use std::fs::File;

use pcap_file::pcapng::PcapNgReader;

/* ----- Main ----- */

/// Prints raw block fields and checks whether each block can be decoded.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcapng/little_endian/basic/test001.pcapng")?;
    let mut reader = PcapNgReader::new(file, true)?;

    while let Some(result) = reader.next_raw_block() {
        match result {
            Ok((raw_block, state)) => {
                println!(
                    "block type: {:#010x}, length: {} bytes",
                    raw_block.type_, raw_block.initial_len
                );

                // A framed block may still have an unknown type or invalid contents.
                match raw_block.try_into_block(state) {
                    Ok(block) => {
                        if let Err(error) = block.validate(state) {
                            eprintln!("invalid block: {error}");
                        }
                    }
                    Err(error) => eprintln!("cannot decode block: {error}"),
                }
            }
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
