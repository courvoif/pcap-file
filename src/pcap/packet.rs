use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use crate::TsResolution;
use crate::errors::*;

/// A valid pcap packet.
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug)]
pub struct PcapPacket<'a> {
    /// Timestamp EPOCH of the packet
    timestamp: Duration,
    /// Original length of the packet when captured on the wire
    orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    data: Cow<'a, [u8]>,
}

impl<'a> PcapPacket<'a> {
    /// Creates a new [`PcapPacket`] with the given parameters.
    pub fn new(timestamp: Duration, orig_len: u32, data: impl Into<Cow<'a, [u8]>>) -> PcapResult<PcapPacket<'a>> {
        let data = data.into();

        // Validate inputs //
        if timestamp.as_secs() > u32::MAX as u64 {
            return Err(PcapError::InvalidField("timestamp_secs > u32::MAX"));
        }

        let Ok(incl_len): Result<u32, _> = data.len().try_into() else {
            return Err(PcapError::InvalidField("data_len > u32::MAX"));
        };

        if incl_len > orig_len {
            return Err(PcapError::InvalidField("orig_len < data_len"));
        }

        Ok(PcapPacket { timestamp, orig_len, data })
    }

    /// Returns the packet timestamp.
    pub fn timestamp(&self) -> Duration {
        self.timestamp
    }

    /// Returns the original length of the packet.
    pub fn orig_len(&self) -> u32 {
        self.orig_len
    }

    /// Returns the length of the packet.
    pub fn len(&self) -> u32 {
        self.data
            .len()
            .try_into()
            .expect("PcapPacket::data_len > u32::MAX, should have been validated on PcapPacket creation")
    }

    /// Returns true if the packet has no payload.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the packet payload as a slice.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the packet payload.
    pub fn into_data(self) -> Cow<'a, [u8]> {
        self.data
    }

    /// Returns an owned version of the packet.
    /// Slower than `into_owned` if the payload is already owned.
    pub fn to_owned(&self) -> PcapPacket<'static> {
        self.clone().into_owned()
    }

    /// Returns an owned version of the packet.
    /// Faster than `to_owned` if the payload is already owned.
    pub fn into_owned(self) -> PcapPacket<'static> {
        PcapPacket { timestamp: self.timestamp, orig_len: self.orig_len, data: Cow::Owned(self.data.into_owned()) }
    }

    /// Tries to create a [`PcapPacket`] from a [`RawPcapPacket`].
    pub fn try_from_raw_packet(raw: RawPcapPacket<'a>, ts_resolution: TsResolution, snap_len: u32) -> PcapResult<Self> {
        // Convert and validate timestamps //
        let ts_sec = raw.ts_sec;
        let mut ts_nsec = raw.ts_frac;

        // Convert original microsecond TS to nanosecond TS
        if ts_resolution == TsResolution::MicroSecond {
            ts_nsec = ts_nsec.checked_mul(1000).ok_or(PcapError::InvalidField("ts_nanosecond is invalid"))?;
        }
        if ts_nsec >= 1_000_000_000 {
            return Err(PcapError::InvalidField("PacketHeader ts_nanosecond >= 1_000_000_000"));
        }

        // Validate lengths //
        let incl_len = raw.incl_len;
        let orig_len = raw.orig_len;

        if incl_len > snap_len {
            return Err(PcapError::InvalidField("PacketHeader incl_len > snap_len"));
        }

        if incl_len > orig_len {
            return Err(PcapError::InvalidField("PacketHeader incl_len > orig_len"));
        }

        Ok(PcapPacket { timestamp: Duration::new(ts_sec as u64, ts_nsec), orig_len, data: raw.data })
    }

    /// Converts a [`PcapPacket`] into a [`RawPcapPacket`].
    pub fn into_raw_packet(self, ts_resolution: TsResolution) -> RawPcapPacket<'a> {
        let (ts_sec, ts_frac, incl_len, orig_len) = self.build_raw_header(ts_resolution);
        RawPcapPacket { ts_sec, ts_frac, incl_len, orig_len, data: self.data }
    }

    /// Converts a [`PcapPacket`] into a [`RawPcapPacket`].
    pub fn as_raw_packet<'pkt>(&'pkt self, ts_resolution: TsResolution) -> RawPcapPacket<'pkt> {
        let (ts_sec, ts_frac, incl_len, orig_len) = self.build_raw_header(ts_resolution);
        RawPcapPacket { ts_sec, ts_frac, incl_len, orig_len, data: Cow::Borrowed(&self.data) }
    }

    /// Builds the raw header fields for a [`RawPcapPacket`].
    fn build_raw_header(&self, ts_resolution: TsResolution) -> (u32, u32, u32, u32) {
        // Transforms PcapPacket::ts into ts_sec and ts_frac //
        let ts_sec: u32 = self
            .timestamp
            .as_secs()
            .try_into()
            .expect("PcapPacket::timestamp_secs > u32::MAX, should have been validated on PcapPacket creation");

        let mut ts_frac = self.timestamp.subsec_nanos();
        if ts_resolution == TsResolution::MicroSecond {
            ts_frac /= 1000;
        }

        let incl_len: u32 = self
            .data
            .len()
            .try_into()
            .expect("PcapPacket::data_len > u32::MAX, should have been validated on PcapPacket creation");

        let orig_len = self.orig_len;

        (ts_sec, ts_frac, incl_len, orig_len)
    }
}

/// Raw Pcap packet with its header and data.
/// The fields of the packet are not validated.
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct RawPcapPacket<'a> {
    /// Timestamp in seconds
    pub ts_sec: u32,
    /// Nanosecond or microsecond part of the timestamp
    pub ts_frac: u32,
    /// Number of octets of the packet saved in file
    pub incl_len: u32,
    /// Original length of the packet on the wire
    pub orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>,
}

impl<'a> RawPcapPacket<'a> {
    /// Parses a new borrowed [`RawPcapPacket`] from a slice.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> PcapResult<(&'a [u8], Self)> {
        // Check header length
        if slice.len() < 16 {
            return Err(PcapError::IncompleteBuffer(16, slice.len()));
        }

        // Read packet header  //
        // Can unwrap because the length check is done before
        let ts_sec = slice.read_u32::<B>().unwrap();
        let ts_frac = slice.read_u32::<B>().unwrap();
        let incl_len = slice.read_u32::<B>().unwrap();
        let orig_len = slice.read_u32::<B>().unwrap();

        let pkt_len = incl_len as usize;
        if slice.len() < pkt_len {
            return Err(PcapError::IncompleteBuffer(pkt_len, slice.len()));
        }

        let packet = RawPcapPacket { ts_sec, ts_frac, incl_len, orig_len, data: Cow::Borrowed(&slice[..pkt_len]) };
        let rem = &slice[pkt_len..];

        Ok((rem, packet))
    }

    /// Writes a [`RawPcapPacket`] to a writer.
    /// The fields of the packet are not validated.
    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W) -> PcapResult<usize> {
        writer.write_u32::<B>(self.ts_sec).map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.ts_frac).map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.incl_len).map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.orig_len).map_err(PcapError::IoError)?;
        writer.write_all(&self.data).map_err(PcapError::IoError)?;

        Ok(16 + self.data.len())
    }

    /// Tries to convert a [`RawPcapPacket`] into a [`PcapPacket`].
    pub fn try_into_pcap_packet(self, ts_resolution: TsResolution, snap_len: u32) -> PcapResult<PcapPacket<'a>> {
        PcapPacket::try_from_raw_packet(self, ts_resolution, snap_len)
    }
}
