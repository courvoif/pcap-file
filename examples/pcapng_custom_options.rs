//! Writes and reads a custom option in a new pcapng capture.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::{Cursor, Write};

use byteorder_slice::byteorder::{ReadBytesExt, WriteBytesExt};
use byteorder_slice::{BigEndian, LittleEndian};
use thiserror::Error;

use pcap_file::DataLink;
use pcap_file::Endianness;
use pcap_file::pcapng::PcapNgState;
use pcap_file::pcapng::blocks::custom::{CustomOptionPayload, CustomPayloadNonCopiable};
use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::blocks::opt_common::CommonOption;
use pcap_file::pcapng::{Block, PcapNgReader, PcapNgWriter};

/* ----- Custom option payload ----- */

/// Sample option payload encoded in the current section byte order.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExampleOptionPayload {
    /// Value carried by this custom option.
    value: u64,
}

/// Errors returned while encoding or decoding the custom option payload.
#[derive(Debug, Error)]
enum OptionPayloadError {
    /// The payload has an unexpected byte length.
    #[error("expected an 8-byte payload, got {0} bytes")]
    InvalidLength(usize),
    /// A byte read or write failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/* ----- Custom option payload traits ----- */

impl<'a> CustomPayloadNonCopiable<'a> for ExampleOptionPayload {
    const PEN: u32 = 70_001;

    type State = PcapNgState;
    type WriteToError = OptionPayloadError;
    type FromSliceError = OptionPayloadError;

    /// Encodes this option using the current section state.
    fn write_to<W: Write>(&self, state: &Self::State, writer: &mut W) -> Result<(), Self::WriteToError> {
        match state.section().endianness {
            Endianness::Big => writer.write_u64::<BigEndian>(self.value)?,
            Endianness::Little => writer.write_u64::<LittleEndian>(self.value)?,
        }
        Ok(())
    }

    /// Decodes this option using the current section state.
    fn from_slice(state: &Self::State, slice: &'a [u8]) -> Result<Option<Self>, Self::FromSliceError> {
        if slice.len() != 8 {
            return Err(OptionPayloadError::InvalidLength(slice.len()));
        }

        let mut bytes = slice;
        let value = match state.section().endianness {
            Endianness::Big => bytes.read_u64::<BigEndian>()?,
            Endianness::Little => bytes.read_u64::<LittleEndian>()?,
        };
        Ok(Some(Self { value }))
    }
}

impl<'a> CustomOptionPayload<'a> for ExampleOptionPayload {}

/* ----- Main ----- */

/// Writes an interface and custom packet option to memory, then decodes it.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), true)?;

    // The packet refers to interface 0, so write that interface first.
    writer.write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535))?;

    // Create the custom option and convert it into an option
    let custom_option = ExampleOptionPayload {
        value: 0xDEAD_BEEF_CAFE_D00D,
    };
    let option = custom_option
        .into_custom_binary_option_non_copiable(writer.state())?
        .into_common_option();

    // Add it to a block and write the block
    let packet = EnhancedPacketBlock {
        original_len: 0,
        data: Cow::Borrowed(&[]),
        options: vec![EnhancedPacketOption::Common(option)],
        ..Default::default()
    };
    writer.write_pcapng_block(packet)?;

    // Read back the data we just write
    let capture = writer.into_inner();
    let mut reader = PcapNgReader::new(Cursor::new(capture), true)?;

    // The 1st block should be the interface block since the section block is consumed by PcapNgReader::new()
    let (first_block, _) = reader.next_block().expect("interface block")?;
    assert!(matches!(first_block, Block::InterfaceDescription(_)));

    // Read the block
    let (block, state) = reader.next_block().expect("packet block")?;
    let Block::EnhancedPacket(packet) = block else {
        panic!("expected an enhanced packet block");
    };

    // Get and decode our custom option
    let Some(EnhancedPacketOption::Common(CommonOption::CustomBinaryNonCopiable(option))) = packet.options.first()
    else {
        panic!("expected a custom option on the packet");
    };
    let actual = option
        .interpret::<ExampleOptionPayload>(state)?
        .expect("custom option PEN should match");

    assert_eq!(
        actual,
        ExampleOptionPayload {
            value: 0xDEAD_BEEF_CAFE_D00D,
        }
    );

    Ok(())
}
