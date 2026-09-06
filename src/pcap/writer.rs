use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::Endianness;
use crate::pcap::{PcapHeader, PcapPacket, PcapTsResolution, PcapValidationError, PcapWriteError};

/// Writes a pcap to a writer.
///
/// # Example
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
    ///     ts_resolution: PcapTsResolution::MicroSecond,
    ///     endianness: Endianness::native()
    /// };
    /// ```
    ///
    /// # Errors
    /// - Returns any error produced by [`Self::with_header`].
    pub fn new(writer: W) -> Result<PcapWriter<W>, PcapWriteError> {
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

    /// Writes a [`PcapPacket`].
    ///
    /// # Errors
    ///
    /// - Returns an error if the captured packet length exceeds the file's
    ///   snaplen.
    /// - Returns an error if the packet cannot be written.
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
    /// The packet fields are not validated; callers are responsible for their correctness.
    /// The resulting pcap file may not be readable by some parsers if the fields are not correct.
    ///
    /// # Errors
    ///
    /// - Returns an error if the raw packet cannot be written.
    pub fn write_raw_packet(&mut self, packet: &RawPcapPacket) -> Result<usize, PcapWriteError> {
        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer),
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer),
        }
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
