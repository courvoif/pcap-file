use std::io::Write;

use byteorder::{ByteOrder, BigEndian, LittleEndian, NativeEndian};

use crate::{DataLink, Endianness, errors::*, pcap::PcapHeader, pcap::PcapPacket, TsResolution};


/// This struct wraps another writer and uses it to write a Pcap formated stream.
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
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
    writer: W
}

impl<W: Write> PcapWriter<W> {
    /// Creates a new `PcapWriter` from an existing writer in the choosen endianess.
    /// Defaults to the native endianness of the CPU.
    ///
    /// Automatically writes this default global pcap header to the file:
    ///
    /// ```rust, ignore
    /// PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: 65535,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: TsResolution::MicroSecond,
    ///     endianness: Endianness::Big
    /// };
    /// ```
    ///
    /// # Errors
    ///
    /// Return an error if the writer can't be written to.
    ///
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::fs::File;
    /// use pcap_file::pcap::PcapWriter;
    ///
    /// let file_out = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_writer = PcapWriter::new(file_out);
    /// ```
    pub fn new(writer: W) -> ResultParsing<PcapWriter<W>> {
        // Get endianness of current processor
        let tmp = NativeEndian::read_u16(&[0x42, 0x00]);
        let endianness = match tmp {
            0x4200 => Endianness::Big,
            0x0042 => Endianness::Little,
            _ => unreachable!()
        };

        let mut header = PcapHeader::default();
        header.endianness = endianness;

        PcapWriter::with_header(writer, header)
    }

    /// Create a new `PcapWriter` from an existing writer with a user defined pcap header.
    ///
    /// The endianness and the timestamp resolution are defined by the magic number of the header.
    /// It is possible to change them with 'set_endianess()' and 'set_ts_resolution()'
    ///
    /// It Automatically writes the pcap header to the file.
    ///
    /// # Errors
    ///
    /// Return an error if the writer can't be written to.
    ///
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::fs::File;
    /// use pcap_file::{
    ///     DataLink, Endianness, TsResolution,
    ///     pcap::{PcapHeader, PcapWriter},
    /// };
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    ///
    /// let header = PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: 65535,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: TsResolution::MicroSecond,
    ///     endianness: Endianness::Big
    /// };
    ///
    /// let mut pcap_writer = PcapWriter::with_header(file, header);
    /// ```
    pub fn with_header(mut writer: W, header: PcapHeader) -> ResultParsing<PcapWriter<W>> {
        header.write_to(&mut writer)?;

        Ok(
            PcapWriter {
                endianness: header.endianness,
                snaplen: header.snaplen,
                ts_resolution: header.ts_resolution,
                writer
            }
        )
    }

    /// Consumes the `PcapWriter`, returning the wrapped writer.
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Writes a `Packet`.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::fs::File;
    /// use std::time::Duration;
    /// use pcap_file::pcap::{
    ///     PcapPacket,
    ///     PcapWriter
    /// };
    ///
    /// let data = [0u8; 10];
    /// let packet = PcapPacket::new(Duration::new(1, 0), data.len() as u32, &data);
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_writer = PcapWriter::new(file).unwrap();
    ///
    /// pcap_writer.write_packet(&packet).unwrap();
    /// ```
    pub fn write_packet(&mut self, packet: &PcapPacket) -> ResultParsing<()> {
        if packet.data.len() > self.snaplen as usize {
            return Err(PcapError::InvalidField("Packet.len > PcapHeader.snap_len"))
        }

        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer, self.ts_resolution)?,
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer, self.ts_resolution)?,
        }

        Ok(())
    }
}
