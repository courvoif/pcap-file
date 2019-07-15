use byteorder::{ByteOrder, BigEndian, LittleEndian, NativeEndian};

use crate::{
    Endianness,
    errors::*,
    pcap::PcapHeader,
    packet::{Packet, PacketHeader}
};

use std::{
    borrow::Cow,
    io::Write
};


/// This struct wraps another writer and uses it to write a Pcap formated stream.
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
/// use pcap_file::pcap::{PcapReader, PcapWriter};
///
///
/// let file_in = File::open("test.pcap").expect("Error opening file");
/// let pcap_reader = PcapReader::new(file_in).unwrap();
///
/// let file_out = File::create("out.pcap").expect("Error creating file out");
/// let mut pcap_writer = PcapWriter::new(file_out).expect("Error writing file");
///
/// // Read test.pcap
/// for pcap in pcap_reader {
///
///     //Check if there is no error
///     let pcap = pcap.unwrap();
///
///     //Write each packet of test.pcap in out.pcap
///     pcap_writer.write_packet(&pcap).unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    pub header: PcapHeader,
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
    ///
    ///     version_major : 2,
    ///     version_minor : 4,
    ///     ts_correction : 0,
    ///     ts_accuracy : 0,
    ///     snaplen : 65535,
    ///     datalink : DataLink::ETHERNET
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

        let tmp = NativeEndian::read_u16(&[0x42, 0x00]);

        let endianness = match tmp {
            0x4200 => Endianness::Big,
            0x0042 => Endianness::Little,
            _ => unreachable!()
        };

        let mut header = PcapHeader::default();
        header.set_endianness(endianness);
        PcapWriter::with_header(header, writer)
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
    ///     DataLink,
    ///     pcap::{PcapHeader, PcapWriter},
    /// };
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    ///
    /// let header = PcapHeader {
    ///
    ///     magic_number : 0xa1b2c3d4,
    ///     version_major : 2,
    ///     version_minor : 4,
    ///     ts_correction : 0,
    ///     ts_accuracy : 0,
    ///     snaplen : 65535,
    ///     datalink : DataLink::ETHERNET
    /// };
    ///
    /// let mut pcap_writer = PcapWriter::with_header(header, file);
    /// ```
    pub fn with_header(header: PcapHeader, mut writer: W) -> ResultParsing<PcapWriter<W>> {

        match header.endianness() {
            Endianness::Big => header.write_to::<_, BigEndian>(&mut writer)?,
            Endianness::Little => header.write_to::<_, LittleEndian>(&mut writer)?,
        }

        Ok(
            PcapWriter {
                header,
                writer
            }
        )
    }

    /// Consumes the `PcapWriter`, returning the wrapped writer.
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Gets a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Writes some raw data, converting it to the pcap file format.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::fs::File;
    /// use pcap_file::pcap::PcapWriter;
    ///
    /// let data = [0u8; 10];
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_writer = PcapWriter::new(file).unwrap();
    ///
    /// pcap_writer.write(1, 0, &data, data.len() as u32).unwrap();
    /// ```
    pub fn write(&mut self, ts_sec: u32, ts_nsec: u32, data: &[u8], orig_len: u32) -> ResultParsing<()> {

        let packet = Packet {

            header: PacketHeader::new(ts_sec, ts_nsec, data.len() as u32, orig_len),
            data: Cow::Borrowed(data)
        };

        self.write_packet(&packet)
    }

    /// Writes a `Packet`.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::fs::File;
    /// use pcap_file::{
    ///     Packet,
    ///     pcap::PcapWriter
    /// };
    ///
    /// let data = [0u8; 10];
    /// let packet = Packet::new(1, 0, &data, data.len() as u32);
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_writer = PcapWriter::new(file).unwrap();
    ///
    /// pcap_writer.write_packet(&packet).unwrap();
    /// ```
    pub fn write_packet(&mut self, packet: &Packet) -> ResultParsing<()> {

        let ts_resolution = self.header.ts_resolution();

        match self.header.endianness() {

            Endianness::Big => packet.header.write_to::<_, BigEndian>(&mut self.writer, ts_resolution)?,
            Endianness::Little => packet.header.write_to::<_, LittleEndian>(&mut self.writer, ts_resolution)?,
        }

        self.writer.write_all(&packet.data)?;

        Ok(())
    }
}
