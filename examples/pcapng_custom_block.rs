use std::error::Error;
use std::fs::File;
use std::io::{self, Write};

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

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "custom-block.pcapng".into());

    let mut writer = PcapNgWriter::new(File::create(&path)?)?;
    writer.write_pcapng_block(Counter(42).into_custom_block_copiable()?)?;
    drop(writer);

    let mut reader = PcapNgReader::new(File::open(path)?)?;
    while let Some(result) = reader.next_block() {
        if let Block::CustomCopiable(block) = result?.0 {
            match block.interpret::<Counter>()? {
                Some(counter) => println!("counter: {}", counter.0),
                None => println!("unrecognized custom block PEN: {}", block.pen),
            }
        }
    }

    Ok(())
}
