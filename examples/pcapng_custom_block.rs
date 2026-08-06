use std::fs::File;
use std::io::{self, BufWriter, Write};

use anyhow::{Context, Result, anyhow};
use byteorder_slice::byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use pcap_file::pcapng::blocks::custom::{CustomBlockPayload, CustomPayloadCopiable};
use pcap_file::pcapng::{Block, PcapNgReader, PcapNgWriter};

#[derive(Clone, Debug)]
struct Counter(u64);

impl CustomPayloadCopiable<'_> for Counter {
    // Obtain a real Private Enterprise Number before publishing a format.
    const PEN: u32 = 70_000;
    type FromSliceError = io::Error;
    type WriteToError = io::Error;

    fn from_slice(slice: &[u8]) -> io::Result<Option<Self>> {
        if slice.len() != 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "counter must be 8 bytes"));
        }
        Ok(Some(Self((&mut &slice[..]).read_u64::<BigEndian>()?)))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u64::<BigEndian>(self.0)
    }
}

impl CustomBlockPayload<'_> for Counter {}

fn main() -> Result<()> {
    let path = "target/pcapng-custom-block-example.pcapng";

    /* Custom block writing */
    let output = File::create(path).context("failed to create the custom-block capture")?;
    let mut writer = PcapNgWriter::new(BufWriter::new(output)).context("failed to write the section header")?;

    let block = Counter(42)
        .into_custom_block_copiable()
        .context("failed to encode the custom block")?;

    writer
        .write_pcapng_block(block)
        .context("failed to write the custom block")?;

    drop(writer);

    /* Custom block reading */
    let input = File::open(path).context("failed to open the custom-block capture")?;
    let mut reader = PcapNgReader::new(input).context("failed to read the section header")?;

    while let Some(result) = reader.next_block() {
        if let Block::CustomCopiable(block) = result.context("failed to read a pcapng block")?.0 {
            let counter = block
                .interpret::<Counter>()
                .context("failed to decode the custom block")?
                .ok_or_else(|| anyhow!("unrecognized custom block PEN: {}", block.pen))?;

            println!("counter: {}", counter.0);
        }
    }

    Ok(())
}
