use std::error::Error;
use std::fs::File;
use std::io::{self, Write};

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

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "custom-option.pcapng".into());

    let custom = CaptureId(1234)
        .into_custom_binary_option_copiable()?
        .into_common_option();
    let section = SectionHeaderBlock {
        options: vec![SectionHeaderOption::Common(custom)],
        ..Default::default()
    };
    PcapNgWriter::with_section_header(File::create(&path)?, section)?;

    // The reader consumes the Section Header Block in new(), so inspect it via section().
    let reader = PcapNgReader::new(File::open(path)?)?;
    for option in &reader.section().options {
        if let SectionHeaderOption::Common(CommonOption::CustomBinaryCopiable(option)) = option {
            match option.interpret::<CaptureId>()? {
                Some(id) => println!("capture ID: {}", id.0),
                None => println!("unrecognized custom option PEN: {}", option.pen),
            }
        }
    }

    Ok(())
}
