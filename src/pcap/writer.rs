//! Classic pcap header and packet writing.

/* ----- Imports ----- */

use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::Endianness;
use crate::pcap::{PcapHeader, PcapPacket, PcapTsResolution, PcapValidationError, PcapWriteError};

/* ----- Writer ----- */

/// Writes a pcap to a writer.
///
/// # Example
/// ```rust,no_run
/// use std::fs::File;
/// use pcap_file::pcap::{PcapReader, PcapWriter};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let file = File::open("tests/pcap/little_endian.pcap")?;
///     let mut reader = PcapReader::new(file)?;
///
///     // Preserve the input datalink, capture limit, and timestamp resolution.
///     let mut writer = PcapWriter::with_header(Vec::new(), reader.header())?;
///     while let Some(result) = reader.next_packet() {
///         // Stop if a packet cannot be read or validated.
///         writer.write_packet(&result?)?;
///     }
///
///     println!("copied {} bytes", writer.into_inner().len());
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    /// Byte order used for encoded header fields.
    endianness: Endianness,
    /// Maximum captured packet length for this file.
    snaplen: u32,
    /// Timestamp resolution written to packet headers.
    ts_resolution: PcapTsResolution,
    /// Destination for encoded capture bytes.
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Creates a new [`PcapWriter`] from an existing writer.
    ///
    /// Writes this default global pcap header to the file:
    /// ```rust
    /// use pcap_file::{DataLink, Endianness};
    /// use pcap_file::pcap::{PcapHeader, PcapTsResolution};
    ///
    /// let header = PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: 65535,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: PcapTsResolution::MicroSecond,
    ///     endianness: Endianness::native()
    /// };
    /// ```
    ///
    /// # Errors
    /// An I/O failure can leave a partial global header in the output.
    pub fn new(writer: W) -> Result<PcapWriter<W>, PcapWriteError> {
        let header = PcapHeader {
            endianness: Endianness::native(),
            ..Default::default()
        };

        PcapWriter::with_header(writer, header)
    }

    /// Creates a new [`PcapWriter`] from an existing writer with a user defined [`PcapHeader`].
    ///
    /// It also writes the pcap header to the file.
    ///
    /// # Errors
    /// An I/O failure can leave a partial global header in the output.
    pub fn with_header(mut writer: W, header: PcapHeader) -> Result<PcapWriter<W>, PcapWriteError> {
        header.write_to(&mut writer)?;

        Ok(PcapWriter {
            endianness: header.endianness,
            snaplen: header.snaplen,
            ts_resolution: header.ts_resolution,
            writer,
        })
    }

    /// Consumes [`PcapWriter`], returning the wrapped writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Writes a validated packet using the capture header's byte order and timestamp resolution.
    /// Microsecond output truncates submicrosecond precision.
    /// An I/O error can leave a partial packet in the output.
    ///
    /// # Errors
    /// Use a capture header whose snaplen is at least the packet's captured length.
    /// If writing fails, assume the output may contain a partial packet.
    pub fn write_packet(&mut self, packet: &PcapPacket) -> Result<usize, PcapWriteError> {
        // Check that the included length of the packet is not bigger than the snaplen of the file
        if packet.len() > self.snaplen {
            return Err(PcapValidationError::PacketLenTooBig(packet.len(), self.snaplen).into());
        }

        let raw_packet = packet.as_raw_packet(self.ts_resolution);
        self.write_raw_packet(&raw_packet)
    }

    /// Writes a [`RawPcapPacket`].
    ///
    /// # Notes
    /// Fields are written without validation.
    /// Match `incl_len` to the data length and use the capture's timestamp resolution.
    ///
    /// # Errors
    /// An I/O failure can leave a partial packet in the output.
    pub fn write_raw_packet(&mut self, packet: &RawPcapPacket) -> Result<usize, PcapWriteError> {
        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer),
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer),
        }
    }

    /// Flushes buffered data to the underlying writer.
    ///
    /// # Errors
    /// Handle the underlying writer's flush failure before treating the capture as saved.
    pub fn flush(&mut self) -> Result<(), PcapWriteError> {
        self.writer.flush().map_err(PcapWriteError::Io)
    }

    /// Returns the endianness used by the writer.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the snaplen used by the writer, i.e. an unsigned value indicating the maximum number of octets captured
    /// from each packet.
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Returns the timestamp resolution of the writer.
    pub fn ts_resolution(&self) -> PcapTsResolution {
        self.ts_resolution
    }
}
