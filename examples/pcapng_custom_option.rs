use std::fs::File;
use std::io::{self, BufWriter, Write};

use anyhow::{Context, Result, anyhow};
use byteorder_slice::byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use pcap_file::pcapng::blocks::custom::{CustomOptionPayload, CustomPayloadCopiable};
use pcap_file::pcapng::blocks::opt_common::CommonOption;
use pcap_file::pcapng::blocks::section_header::{SectionHeaderBlock, SectionHeaderOption};
use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};

#[derive(Clone, Debug)]
struct CaptureId(u64);

impl CustomPayloadCopiable<'_> for CaptureId {
    // Obtain a real Private Enterprise Number before publishing a format.
    const PEN: u32 = 70_000;
    type FromSliceError = io::Error;
    type WriteToError = io::Error;

    fn from_slice(slice: &[u8]) -> io::Result<Option<Self>> {
        if slice.len() != 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "capture ID must be 8 bytes"));
        }
        Ok(Some(Self((&mut &slice[..]).read_u64::<BigEndian>()?)))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u64::<BigEndian>(self.0)
    }
}

impl CustomOptionPayload<'_> for CaptureId {}

fn main() -> Result<()> {
    let path = "target/pcapng-custom-option-example.pcapng";

    let custom = CaptureId(1234)
        .into_custom_binary_option_copiable()
        .context("failed to encode the custom option")?
        .into_common_option();

    // We could have added the option to any block.
    // We use a SectionHeaderBlock for the sake of simplicity.
    let section = SectionHeaderBlock {
        options: vec![SectionHeaderOption::Common(custom)],
        ..Default::default()
    };

    let output = File::create(path).context("failed to create the custom-option capture")?;
    let writer = PcapNgWriter::with_section_header(BufWriter::new(output), section)
        .context("failed to write the section header and custom option")?;
    drop(writer);

    // The reader consumes the Section Header Block in new(), so inspect it via section().
    let input = File::open(path).context("failed to open the custom-option capture")?;
    let reader = PcapNgReader::new(input).context("failed to read the section header")?;

    for option in &reader.section().options {
        if let SectionHeaderOption::Common(CommonOption::CustomBinaryCopiable(option)) = option {
            let capture_id = option
                .interpret::<CaptureId>()
                .context("failed to decode the custom option")?
                .ok_or_else(|| anyhow!("unrecognized custom option PEN: {}", option.pen))?;

            println!("capture ID: {}", capture_id.0);
        }
    }

    Ok(())
}
