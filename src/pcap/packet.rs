use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use crate::pcap::PcapTsResolution;
use crate::pcap::errors::{PcapPacketConversionError, PcapParseError, PcapValidationError, PcapWriteError};

/// A valid pcap packet.
///
/// The packet data can be owned or borrowed.
#[derive(Clone, Debug)]
pub struct PcapPacket<'a> {
    /// Time elapsed since the Unix epoch.
    timestamp: Duration,
    /// Original length of the packet on the wire.
    original_len: u32,
    /// Owned or borrowed packet data.
    data: Cow<'a, [u8]>,
}

impl<'a> PcapPacket<'a> {
    /// Creates a new [`PcapPacket`] with the given parameters.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapValidationError::TimestampTooBig`] if the timestamp in seconds
    ///   cannot be represented on a u32.
    /// - Returns [`PcapValidationError::DataTooBig`] if the packet data is
    ///   larger than `u32::MAX` bytes.
    /// - Returns [`PcapValidationError::OriginalLenTooSmall`] if `original_len` is
    ///   smaller than the packet data length.
    pub fn new(
        timestamp: Duration,
        original_len: u32,
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

        if incl_len > original_len {
            return Err(PcapValidationError::OriginalLenTooSmall(original_len, incl_len));
        }

        Ok(PcapPacket {
            timestamp,
            original_len,
            data,
        })
    }

    /// Returns the packet timestamp.
    pub fn timestamp(&self) -> Duration {
        self.timestamp
    }

    /// Returns the packet's original length on the wire.
    pub fn original_len(&self) -> u32 {
        self.original_len
    }

    /// Returns the length of the packet.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the packet has no data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the packet data as a slice.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the packet data, preserving whether it is borrowed or owned.
    pub fn into_data(self) -> Cow<'a, [u8]> {
        self.data
    }

    /// Returns an owned version of the packet.
    /// Faster than `to_owned` if the packet data is already owned.
    pub fn into_owned(self) -> PcapPacket<'static> {
        PcapPacket {
            timestamp: self.timestamp,
            original_len: self.original_len,
            data: Cow::Owned(self.data.into_owned()),
        }
    }

    /// Tries to create a [`PcapPacket`] from a [`RawPcapPacket`].
    ///
    /// # Errors
    ///
    /// - Returns a [`PcapPacketConversionError`] if the raw packet fields are
    ///   invalid. The error contains the original packet, which can be
    ///   inspected, corrected, and passed to this method again.
    pub fn try_from_raw_packet(
        raw: RawPcapPacket<'a>,
        ts_resolution: PcapTsResolution,
        snap_len: u32,
    ) -> Result<Self, PcapPacketConversionError<'a>> {
        // Convert and validate timestamps //
        let ts_sec = raw.ts_sec;

        // Convert original microsecond TS to nanosecond TS
        let ts_nsec = if ts_resolution == PcapTsResolution::Microsecond {
            let ts_usec = raw.ts_frac;
            if ts_usec >= 1_000_000 {
                return Err(PcapPacketConversionError {
                    packet: raw,
                    source: PcapValidationError::TsFracMicroTooBig(ts_usec),
                });
            }

            ts_usec
                .checked_mul(1000)
                .expect("ts_usec * 1000 overflow, should have been validated just before")
        } else {
            let ts_nsec = raw.ts_frac;
            if ts_nsec >= 1_000_000_000 {
                return Err(PcapPacketConversionError {
                    packet: raw,
                    source: PcapValidationError::TsFracNanoTooBig(ts_nsec),
                });
            }

            ts_nsec
        };

        let timestamp = Duration::new(ts_sec as u64, ts_nsec);

        // Validate lengths //
        if raw.incl_len > snap_len {
            return Err(PcapPacketConversionError {
                source: PcapValidationError::PacketTooBig(raw.incl_len, snap_len),
                packet: raw,
            });
        }

        let Ok(data_len): Result<u32, _> = raw.data.len().try_into() else {
            return Err(PcapPacketConversionError {
                source: PcapValidationError::DataTooBig(raw.data.len()),
                packet: raw,
            });
        };

        if raw.incl_len != data_len {
            return Err(PcapPacketConversionError {
                source: PcapValidationError::IncludedLenMismatch(raw.incl_len, data_len),
                packet: raw,
            });
        }

        if data_len > raw.orig_len {
            return Err(PcapPacketConversionError {
                source: PcapValidationError::OriginalLenTooSmall(raw.orig_len, data_len),
                packet: raw,
            });
        }

        Ok(Self {
            timestamp,
            original_len: raw.orig_len,
            data: raw.data,
        })
    }

    /// Converts a [`PcapPacket`] into a [`RawPcapPacket`].
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

    /// Converts a [`PcapPacket`] into a [`RawPcapPacket`].
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
        if ts_resolution == PcapTsResolution::Microsecond {
            ts_frac /= 1000;
        }

        let incl_len: u32 = self
            .data
            .len()
            .try_into()
            .expect("PcapPacket::data_len > u32::MAX, should have been validated on PcapPacket creation");

        let orig_len = self.original_len;

        (ts_sec, ts_frac, incl_len, orig_len)
    }
}

/// Raw pcap packet header and packet data.
///
/// Header fields are not validated, and the packet data can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct RawPcapPacket<'a> {
    /// Whole-second component of the timestamp.
    pub ts_sec: u32,
    /// Fractional timestamp component, interpreted using the file's resolution.
    pub ts_frac: u32,
    /// Number of packet bytes stored in the file.
    pub incl_len: u32,
    /// Original packet length on the wire.
    pub orig_len: u32,
    /// Owned or borrowed packet data.
    pub data: Cow<'a, [u8]>,
}

impl<'a> RawPcapPacket<'a> {
    /// Parses a new borrowed [`RawPcapPacket`] from a slice.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapParseError::IncompleteBuffer`] if the input does not
    ///   contain the complete packet header and packet data.
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

    /// Writes a [`RawPcapPacket`] without validating its fields.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// - Returns an error if the packet header or packet data cannot be written.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> Result<usize, PcapWriteError> {
        writer.write_u32::<B>(self.ts_sec)?;
        writer.write_u32::<B>(self.ts_frac)?;
        writer.write_u32::<B>(self.incl_len)?;
        writer.write_u32::<B>(self.orig_len)?;
        writer.write_all(&self.data)?;

        Ok(16 + self.data.len())
    }

    /// Tries to convert a [`RawPcapPacket`] into a [`PcapPacket`].
    ///
    /// # Errors
    ///
    /// - Returns a [`PcapPacketConversionError`] if this raw packet is invalid.
    ///   The error contains the original packet, which can be inspected,
    ///   corrected, and passed to this method again.
    pub fn try_into_pcap_packet(
        self,
        ts_resolution: PcapTsResolution,
        snap_len: u32,
    ) -> Result<PcapPacket<'a>, PcapPacketConversionError<'a>> {
        PcapPacket::try_from_raw_packet(self, ts_resolution, snap_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_raw_packet_rejects_included_len_mismatch() {
        let raw_packet = RawPcapPacket {
            ts_sec: 1,
            ts_frac: 0,
            incl_len: 2,
            orig_len: 4,
            data: Cow::Borrowed(&[1, 2, 3, 4]),
        };

        // Typed conversion must not silently replace the raw included length
        // with the actual packet data length.
        let error = PcapPacket::try_from_raw_packet(raw_packet, PcapTsResolution::Microsecond, 65_535).unwrap_err();
        assert!(matches!(error.source, PcapValidationError::IncludedLenMismatch(2, 4)));
        assert_eq!(error.packet.incl_len, 2);
        assert_eq!(&*error.packet.data, &[1, 2, 3, 4]);
    }
}
