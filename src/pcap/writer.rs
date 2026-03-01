use std::io::Write;

use byteorder_slice::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::errors::*;
use crate::pcap::{PcapError, PcapHeader, PcapPacket, PcapValidationError};
use crate::{Endianness, TsResolution};

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
///     //Check if there is no error
///     let pkt = pkt.unwrap();
///
///     //Write each packet of test.pcap in out.pcap
///     pcap_writer.write_packet(&pkt).unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    endianness: Endianness,
    snaplen: u32,
    ts_resolution: TsResolution,
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Creates a new [`PcapWriter`] from an existing writer.
    ///
    /// Defaults to the native endianness of the CPU.
    ///
    /// Writes this default global pcap header to the file:
    /// ```rust, ignore
    /// PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: 65535,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: TsResolution::MicroSecond,
    ///     endianness: Endianness::Native
    /// };
    /// ```
    ///
    /// # Errors
    /// The writer can't be written to.
    pub fn new(writer: W) -> Result<PcapWriter<W>, PcapError> {
        let header = PcapHeader { endianness: Endianness::native(), ..Default::default() };

        PcapWriter::with_header(writer, header)
    }

    /// Creates a new [`PcapWriter`] from an existing writer with a user defined [`PcapHeader`].
    ///
    /// It also writes the pcap header to the file.
    ///
    /// # Errors
    /// The writer can't be written to.
    pub fn with_header(mut writer: W, header: PcapHeader) -> Result<PcapWriter<W>, PcapError> {
        header.write_to(&mut writer)?;

        Ok(PcapWriter {
            endianness: header.endianness,
            snaplen: header.snaplen,
            ts_resolution: header.ts_resolution,
            writer,
        })
    }

    /// Consumes [`Self`], returning the wrapped writer.
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Writes a [`PcapPacket`].
    ///
    /// # Errors
    /// The included length of the packet must not be bigger than the snaplen of the file, otherwise an error is returned.
    pub fn write_packet(&mut self, packet: &PcapPacket) -> Result<usize, PcapError> {
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
    /// The fields of the packet are not validated, it is the responsibility of the user to check that they are correct.
    /// The resulting pcap file may not be readable by some parsers if the fields are not correct.
    pub fn write_raw_packet(&mut self, packet: &RawPcapPacket) -> Result<usize, PcapError> {
        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer),
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer),
        }
    }

    /// Flush data
    pub fn flush(&mut self) -> Result<(), PcapError> {
        self.writer.flush().map_err(PcapError::WriteFailed)
    }

    /// Returns the endianess used by the writer.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the snaplen used by the writer, i.e. an unsigned value indicating the maximum number of octets captured
    /// from each packet.
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Returns the timestamp resolution of the writer.
    pub fn ts_resolution(&self) -> TsResolution {
        self.ts_resolution
    }
}
