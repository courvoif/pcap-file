//! Reads blocks from an existing pcapng test capture.

/* ----- Imports ----- */

use std::fs::File;

use pcap_file::pcapng::PcapNgReader;

/* ----- Main ----- */

/// Reads and prints the type of each block in the fixture.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcapng/little_endian/basic/test001.pcapng")?;
    let mut reader = PcapNgReader::new(file, true)?;

    while let Some(result) = reader.next_block() {
        match result {
            Ok((block, _state)) => println!(
                "block type: {:#010x}",
                block.type_code()
            ),
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}
