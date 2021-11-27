use byteorder_slice::{ByteOrder, ReadSlice};
use byteorder_slice::byteorder::WriteBytesExt;
use derive_into_owned::IntoOwned;

use crate::{
    errors::*,
    TsResolution
};

use std::{
    borrow::Cow,
    io::Write,
    time::Duration
};


/// Pcap packet with its header and data.
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct PcapPacket<'a> {
    /// Timestamp EPOCH of the packet with a nanosecond resolution
    pub timestamp: Duration,
    /// Original length of the packet when captured on the wire
    pub orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>
}

impl<'a> PcapPacket<'a> {
    /// Create a new borrowed `Packet` with the given parameters.
    pub fn new(timestamp: Duration, orig_len: u32, data: &'a [u8]) -> PcapPacket<'a> {
        PcapPacket {
            timestamp,
            orig_len,
            data: Cow::Borrowed(data),
        }
    }

    /// Create a new owned `Packet` with the given parameters.
    pub fn new_owned(timestamp: Duration, orig_len: u32, data: Vec<u8>) -> PcapPacket<'static> {
        PcapPacket {
            timestamp,
            orig_len,
            data: Cow::Owned(data)
        }
    }

    /// Parse a new borrowed `Packet` from a slice.
    pub fn from_slice<B: ByteOrder>(slice: &'a [u8], ts_resolution: TsResolution, snap_len: u32) -> PcapResult<(&'a [u8], PcapPacket<'a>)> {
        let (slice, header) = PacketHeader::from_slice::<B>(slice, ts_resolution, snap_len)?;
        let len = header.incl_len as usize;

        if slice.len() < len {
            return Err(PcapError::IncompleteBuffer(len - slice.len()));
        }

        let packet = PcapPacket {
            timestamp: Duration::new(header.ts_sec as u64, header.ts_nsec),
            orig_len: header.orig_len,
            data : Cow::Borrowed(&slice[..len])
        };

        let slice = &slice[len..];

        Ok((slice, packet))
    }

    /// Write a `Packet` to a writer.
    ///
    /// Writes 24B in the writer on success.
    pub fn write_to< W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution) -> PcapResult<()> {
        let ts_sec = self.timestamp.as_secs();
        let ts_nsec = self.timestamp.subsec_nanos();
        let incl_len = self.data.len();
        let orig_len = self.orig_len;

        if ts_sec > u32::MAX as u64 {
            return Err(PcapError::InvalidField("PcapPacket: timestamp_secs > u32::MAX"));
        }

        if incl_len > 0xFFFF {
            return Err(PcapError::InvalidField("PcapPacket: incl_len > 0XFFFF"));
        }

        if incl_len > orig_len as usize {
            return Err(PcapError::InvalidField("PcapPacket: incl_len > orig_len"));
        }

        let header = PacketHeader {
            ts_sec: ts_sec as u32,
            ts_nsec,
            incl_len: incl_len as u32,
            orig_len
        };
        header.write_to::<_, B>(writer, ts_resolution)?;
        writer.write_all(&self.data)?;

        Ok(())
    }
}

/// Pcap packet header
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
struct PacketHeader {
    /// Timestamp in seconds
    ts_sec: u32,
    /// Nanosecond part of the timestamp
    ts_nsec: u32,
    /// Number of octets of the packet saved in file
    incl_len: u32,
    /// Original length of the packet on the wire
    orig_len: u32
}

impl PacketHeader {
    /// Creates a new `PacketHeader` from a slice.
    pub(crate) fn from_slice<B: ByteOrder>(mut slice: &[u8], ts_resolution: TsResolution, snap_len: u32) -> PcapResult<(&[u8], PacketHeader)> {
        // Check header length
        if slice.len() < 16 {
            return Err(PcapError::IncompleteBuffer(16 - slice.len()));
        }

        ////// Parse the header ///////

        // Read and validate timestamps
        let ts_sec = slice.read_u32::<B>()?;
        let mut ts_nsec = slice.read_u32::<B>()?;
        if ts_resolution == TsResolution::MicroSecond {
            ts_nsec = ts_nsec.checked_mul(1000).ok_or(PcapError::InvalidField("Packet Header ts_microsecond can't be converted to nanosecond"))?;
        }
        if ts_nsec >= 1_000_000_000 {
            return Err(PcapError::InvalidField("Packet Header ts_nanosecond >= 1_000_000_000"));
        }

        let incl_len = slice.read_u32::<B>()?;
        let orig_len = slice.read_u32::<B>()?;

        if incl_len > snap_len {
            return Err(PcapError::InvalidField("PacketHeader incl_len > snap_len"));
        }

        if orig_len > snap_len {
            return Err(PcapError::InvalidField("PacketHeader orig_len > snap_len"));
        }

        if incl_len > orig_len {
            return Err(PcapError::InvalidField("PacketHeader incl_len > orig_len"));
        }

        let header = PacketHeader {
            ts_sec,
            ts_nsec,
            incl_len,
            orig_len
        };

        Ok((slice, header))
    }

    /// Write a `PcapHeader` to a writer.
    ///
    /// Writes 24B in the writer on success.
    pub(crate) fn write_to< W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution) -> PcapResult<()> {
        let mut ts_unsec = self.ts_nsec;
        if ts_resolution == TsResolution::MicroSecond {
            ts_unsec /= 1000;
        }

        writer.write_u32::<B>(self.ts_sec)?;
        writer.write_u32::<B>(ts_unsec)?;
        writer.write_u32::<B>(self.incl_len)?;
        writer.write_u32::<B>(self.orig_len)?;

        Ok(())
    }
}
