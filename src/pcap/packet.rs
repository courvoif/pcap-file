//! Validated and raw classic pcap packet records.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use crate::pcap::{PcapParseError, PcapTsResolution, PcapValidationError, PcapWriteError};

/* ----- Validated packets ----- */

/// A valid pcap packet.
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug)]
pub struct PcapPacket<'a> {
    /// Time elapsed since 1970-01-01 00:00:00 UTC.
    timestamp: Duration,
    /// Original length of the packet when captured on the wire
    orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    data: Cow<'a, [u8]>,
}

impl<'a> PcapPacket<'a> {
    /// Creates a validated packet from its timestamp, original length, and captured bytes.
    /// `timestamp` is the time elapsed since the Unix epoch.
    ///
    /// # Errors
    /// Keep the seconds and captured length within `u32::MAX`.
    /// Set `orig_len` to at least the captured data length.
    pub fn new(
        timestamp: Duration,
        orig_len: u32,
        data: impl Into<Cow<'a, [u8]>>,
    ) -> Result<Self, PcapValidationError> {
        let data = data.into();

        // Validate inputs //
        if timestamp.as_secs() > u32::MAX as u64 {
            return Err(PcapValidationError::TimestampTooBig(timestamp));
        }

        let Ok(incl_len): Result<u32, _> = data.len().try_into() else {
            return Err(PcapValidationError::DataTooBig(data.len()));
        };

        if incl_len > orig_len {
            return Err(PcapValidationError::OriginLenTooSmall(orig_len, incl_len));
        }

        Ok(PcapPacket {
            timestamp,
            orig_len,
            data,
        })
    }

    /// Returns the time elapsed since 1970-01-01 00:00:00 UTC.
    pub fn timestamp(&self) -> Duration {
        self.timestamp
    }

    /// Returns the original length of the packet.
    pub fn orig_len(&self) -> u32 {
        self.orig_len
    }

    /// Returns the captured data length in bytes.
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

    /// Returns captured bytes, including link-layer headers, as a slice.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the captured bytes, retaining their ownership.
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
        PcapPacket {
            timestamp: self.timestamp,
            orig_len: self.orig_len,
            data: Cow::Owned(self.data.into_owned()),
        }
    }

    /// Converts raw packet fields into a validated packet using the capture header settings.
    ///
    /// # Errors
    /// Correct the fractional timestamp or lengths before retrying.
    /// The declared captured length must match the data length.
    /// The declared captured length must not exceed `snap_len`, and the original
    /// length must not be smaller than the data length.
    pub fn try_from_raw_packet(
        raw: RawPcapPacket<'a>,
        ts_resolution: PcapTsResolution,
        snap_len: u32,
    ) -> Result<Self, PcapValidationError> {
        // Convert and validate timestamps //
        let ts_sec = raw.ts_sec;

        // Convert original microsecond TS to nanosecond TS
        let ts_nsec = if ts_resolution == PcapTsResolution::MicroSecond {
            let ts_usec = raw.ts_frac;
            if ts_usec >= 1_000_000 {
                return Err(PcapValidationError::TsFracMicroTooBig(ts_usec));
            }

            ts_usec
                .checked_mul(1000)
                .expect("ts_usec * 1000 overflow, should have been validated just before")
        } else {
            let ts_nsec = raw.ts_frac;
            if ts_nsec >= 1_000_000_000 {
                return Err(PcapValidationError::TsFracNanoTooBig(raw.ts_frac));
            }

            ts_nsec
        };

        let timestamp = Duration::new(ts_sec as u64, ts_nsec);

        // Validate lengths //
        if raw.incl_len as usize != raw.data.len() {
            return Err(PcapValidationError::IncludedLenMismatch(raw.incl_len, raw.data.len()));
        }

        if raw.incl_len > snap_len {
            return Err(PcapValidationError::IncludedLenTooBig(raw.incl_len, snap_len));
        }

        Self::new(timestamp, raw.orig_len, raw.data)
    }

    /// Converts this packet into raw fields, retaining its data ownership.
    /// Microsecond resolution truncates submicrosecond precision.
    pub fn into_raw_packet(self, ts_resolution: PcapTsResolution) -> RawPcapPacket<'a> {
        let (ts_sec, ts_frac, incl_len, orig_len) = self.build_raw_header(ts_resolution);
        RawPcapPacket {
            ts_sec,
            ts_frac,
            incl_len,
            orig_len,
            data: self.data,
        }
    }

    /// Returns raw fields borrowing this packet's captured bytes.
    /// Microsecond resolution truncates submicrosecond precision.
    pub fn as_raw_packet<'pkt>(&'pkt self, ts_resolution: PcapTsResolution) -> RawPcapPacket<'pkt> {
        let (ts_sec, ts_frac, incl_len, orig_len) = self.build_raw_header(ts_resolution);
        RawPcapPacket {
            ts_sec,
            ts_frac,
            incl_len,
            orig_len,
            data: Cow::Borrowed(&self.data),
        }
    }

    /// Builds the raw header fields for a [`RawPcapPacket`].
    fn build_raw_header(&self, ts_resolution: PcapTsResolution) -> (u32, u32, u32, u32) {
        // Transforms PcapPacket::ts into ts_sec and ts_frac //
        let ts_sec: u32 = self
            .timestamp
            .as_secs()
            .try_into()
            .expect("PcapPacket::timestamp_secs > u32::MAX, should have been validated on PcapPacket creation");

        let mut ts_frac = self.timestamp.subsec_nanos();
        if ts_resolution == PcapTsResolution::MicroSecond {
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

/* ----- Raw packets ----- */

/// Raw Pcap packet with its header and data.
/// The fields of the packet are not validated.
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct RawPcapPacket<'a> {
    /// Whole seconds elapsed since the Unix epoch.
    pub ts_sec: u32,
    /// Fractional timestamp ticks in the resolution specified by the global header.
    pub ts_frac: u32,
    /// Number of octets of the packet saved in file
    pub incl_len: u32,
    /// Original length of the packet on the wire
    pub orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>,
}

impl<'a> RawPcapPacket<'a> {
    /// Returns the next borrowed raw packet and the remaining input using byte order `B`.
    ///
    /// # Errors
    /// Supply the complete 16-byte header and the payload declared by `incl_len`.
    /// Retry incomplete input with additional bytes.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapParseError> {
        // Check header length
        if slice.len() < 16 {
            return Err(PcapParseError::IncompleteBuffer(16, slice.len()));
        }

        // Read packet header  //
        let ts_sec = slice.read_u32::<B>().expect("slice length checked above");
        let ts_frac = slice.read_u32::<B>().expect("slice length checked above");
        let incl_len = slice.read_u32::<B>().expect("slice length checked above");
        let orig_len = slice.read_u32::<B>().expect("slice length checked above");

        let pkt_len = incl_len as usize;
        if slice.len() < pkt_len {
            return Err(PcapParseError::IncompleteBuffer(pkt_len, slice.len()));
        }

        let packet = RawPcapPacket {
            ts_sec,
            ts_frac,
            incl_len,
            orig_len,
            data: Cow::Borrowed(&slice[..pkt_len]),
        };
        let rem = &slice[pkt_len..];

        Ok((rem, packet))
    }

    /// Writes a [`RawPcapPacket`] to a writer.
    /// Fields are written using `B` without semantic validation.
    /// Match `incl_len` to the captured data length when constructing records manually.
    ///
    /// # Errors
    /// An I/O failure can leave a partial packet in the output.
    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W) -> Result<usize, PcapWriteError> {
        writer
            .write_u32::<B>(self.ts_sec)
            .map_err(|e| PcapWriteError::FieldWriteFailed("ts_sec", e))?;
        writer
            .write_u32::<B>(self.ts_frac)
            .map_err(|e| PcapWriteError::FieldWriteFailed("ts_frac", e))?;
        writer
            .write_u32::<B>(self.incl_len)
            .map_err(|e| PcapWriteError::FieldWriteFailed("incl_len", e))?;
        writer
            .write_u32::<B>(self.orig_len)
            .map_err(|e| PcapWriteError::FieldWriteFailed("orig_len", e))?;
        writer
            .write_all(&self.data)
            .map_err(|e| PcapWriteError::FieldWriteFailed("data", e))?;

        Ok(16 + self.data.len())
    }

    /// Converts this record to a validated packet using the capture header settings.
    /// See [`PcapPacket::try_from_raw_packet`] for validation and errors.
    pub fn try_into_pcap_packet(
        self,
        ts_resolution: PcapTsResolution,
        snap_len: u32,
    ) -> Result<PcapPacket<'a>, PcapValidationError> {
        PcapPacket::try_from_raw_packet(self, ts_resolution, snap_len)
    }
}
