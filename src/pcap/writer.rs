//! pcap stream writing.

use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::Endianness;
use crate::pcap::errors::{PcapValidationError, PcapWriteError};
use crate::pcap::{PcapHeader, PcapPacket, PcapTsResolution};

/// Writes a pcap to a writer.
///
/// # Examples
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcap::{PcapReader, PcapWriter};
///
/// let file_in = File::open("test.pcap").expect("Error opening file");
/// let mut pcap_reader = PcapReader::new(file_in).unwrap();
///
/// let file_out = File::create("out.pcap").expect("Error creating file out");
/// let mut pcap_writer = PcapWriter::new(file_out).expect("Error writing file");
///
/// // Read test.pcap
/// while let Some(pkt) = pcap_reader.next_packet() {
///     let pkt = pkt.unwrap();
///
///     // Write the packet to out.pcap.
///     pcap_writer.write_packet(&pkt).unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    endianness: Endianness,
    snaplen: u32,
    ts_resolution: PcapTsResolution,
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
    ///     ts_resolution: PcapTsResolution::Microsecond,
    ///     endianness: Endianness::native()
    /// };
    /// ```
    ///
    /// # Errors
    /// - Returns any error produced by [`Self::with_header`].
    pub fn new(writer: W) -> Result<Self, PcapWriteError> {
        let header = PcapHeader {
            endianness: Endianness::native(),
            ..Default::default()
        };

        PcapWriter::with_header(writer, header)
    }

    /// Creates a new [`PcapWriter`] with a user-defined [`PcapHeader`].
    ///
    /// It also writes the pcap header to the file.
    ///
    /// # Errors
    /// - Returns any error produced by [`PcapHeader::write_to`].
    pub fn with_header(mut writer: W, header: PcapHeader) -> Result<Self, PcapWriteError> {
        header.write_to(&mut writer)?;

        Ok(PcapWriter {
            endianness: header.endianness,
            snaplen: header.snaplen,
            ts_resolution: header.ts_resolution,
            writer,
        })
    }

    /// Consumes the [`PcapWriter`], returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Returns a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Returns a mutable reference to the underlying writer.
    ///
    /// Writing directly to the underlying writer can produce an invalid pcap
    /// stream.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Writes a [`PcapPacket`].
    ///
    /// After an I/O error, callers should assume the pcap stream is no longer usable.
    ///
    /// # Errors
    ///
    /// - Returns an error if the captured packet length exceeds the file's
    ///   snaplen.
    /// - Returns an error if the packet cannot be written.
    pub fn write_packet(&mut self, packet: &PcapPacket) -> Result<usize, PcapWriteError> {
        // Check that the included length of the packet is not bigger than the snaplen of the file
        if packet.len() > self.snaplen as usize {
            let packet_len = u32::try_from(packet.len()).expect("PcapPacket length is validated during construction");
            return Err(PcapValidationError::CapturedLengthExceedsSnaplen(packet_len, self.snaplen).into());
        }

        let raw_packet = packet.as_raw_packet(self.ts_resolution);
        self.write_raw_packet(&raw_packet)
    }

    /// Writes a [`RawPcapPacket`].
    ///
    /// After an I/O error, callers should assume the pcap stream is no longer usable.
    ///
    /// # Notes
    /// The packet fields are not validated; callers are responsible for their correctness.
    /// The resulting pcap file may not be readable by some parsers if the fields are not correct.
    ///
    /// # Errors
    ///
    /// - Returns an error if the raw packet cannot be written.
    pub fn write_raw_packet(&mut self, packet: &RawPcapPacket) -> Result<usize, PcapWriteError> {
        match self.endianness {
            Endianness::Big => packet.write_to::<BigEndian, _>(&mut self.writer),
            Endianness::Little => packet.write_to::<LittleEndian, _>(&mut self.writer),
        }
    }

    /// Returns the endianness used by the writer.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the maximum number of bytes captured from each packet.
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Returns the timestamp resolution of the writer.
    pub fn ts_resolution(&self) -> PcapTsResolution {
        self.ts_resolution
    }
}
