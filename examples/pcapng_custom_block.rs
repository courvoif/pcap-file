//! Writes and reads a custom block whose timestamp depends on pcapng state.

/* ----- Imports ----- */

use std::io::{Cursor, Write};
use std::time::Duration;

use byteorder_slice::BigEndian;
use byteorder_slice::byteorder::{ReadBytesExt, WriteBytesExt};
use thiserror::Error;

use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgState;
use pcap_file::pcapng::blocks::custom::{CustomBlockPayload, CustomPayloadNonCopiable};
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::errors::TimestampError;
use pcap_file::pcapng::{Block, PcapNgReader, PcapNgWriter};

/* ----- Custom payload ----- */

/// Stores an interface ID and timestamp as three big endian words.
/// The timestamp uses the interface resolution from pcapng state.
#[derive(Clone, Debug, Eq, PartialEq)]
struct StatefulPayload {
    /// Interface that supplies the timestamp resolution.
    interface_id: u32,
    /// Timestamp represented in this custom block.
    timestamp: Duration,
}

/// Errors returned when the custom payload cannot be encoded or decoded.
#[derive(Debug, Error)]
enum PayloadError {
    /// The payload has an unexpected byte length.
    #[error("expected a 12-byte payload, got {0} bytes")]
    InvalidLength(usize),
    /// Reading or writing payload bytes failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The timestamp cannot be represented using the interface settings.
    #[error(transparent)]
    Timestamp(#[from] TimestampError),
}

/* ----- Custom block implementation ----- */

impl<'a> CustomPayloadNonCopiable<'a> for StatefulPayload {
    const PEN: u32 = 70_000;

    type State = PcapNgState;
    type WriteToError = PayloadError;
    type FromSliceError = PayloadError;

    /// Writes the payload using the current interface timestamp settings.
    fn write_to<W: Write>(&self, state: &Self::State, writer: &mut W) -> Result<(), Self::WriteToError> {
        let (high, low) = state.encode_timestamp(self.interface_id, self.timestamp)?;
        writer.write_u32::<BigEndian>(self.interface_id)?;
        writer.write_u32::<BigEndian>(high)?;
        writer.write_u32::<BigEndian>(low)?;
        Ok(())
    }

    /// Reads the payload using the current interface timestamp settings.
    fn from_slice(state: &Self::State, slice: &'a [u8]) -> Result<Option<Self>, Self::FromSliceError> {
        if slice.len() != 12 {
            return Err(PayloadError::InvalidLength(slice.len()));
        }

        let mut bytes = slice;
        let interface_id = bytes.read_u32::<BigEndian>()?;
        let high = bytes.read_u32::<BigEndian>()?;
        let low = bytes.read_u32::<BigEndian>()?;
        let timestamp = state.decode_timestamp(interface_id, high, low)?;

        Ok(Some(Self {
            interface_id,
            timestamp,
        }))
    }
}

impl<'a> CustomBlockPayload<'a> for StatefulPayload {}

/* ----- Main ----- */

/// Writes a custom block to memory, then reads and checks its payload.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), true)?;

    // The payload uses interface 0, so add that interface to the writer state first.
    let interface = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535);
    writer.write_pcapng_block(interface)?;

    // Create and write the custom block
    let custom_payload = StatefulPayload {
        interface_id: 0,
        timestamp: Duration::from_secs(1),
    };
    let custom_block = custom_payload.into_custom_block_non_copiable(writer.state())?;
    writer.write_pcapng_block(custom_block)?;

    // Read back the data we just write
    let capture = writer.into_inner();
    let mut reader = PcapNgReader::new(Cursor::new(capture), true)?;

    // The 1st block should be the interface block since the section block is consumed by PcapNgReader::new()
    let (first_block, _) = reader.next_block().expect("interface block")?;
    assert!(matches!(first_block, Block::InterfaceDescription(_)));

    // Read and decode our custom block
    let (block, state) = reader.next_block().expect("custom block")?;
    let Block::CustomNonCopiable(custom_block) = block else {
        panic!("expected a custom block");
    };
    let custom_payload = custom_block
        .interpret::<StatefulPayload>(state)?
        .expect("custom block should be a StatefulPayload");

    assert_eq!(
        custom_payload,
        StatefulPayload {
            interface_id: 0,
            timestamp: Duration::from_secs(1),
        }
    );

    Ok(())
}
