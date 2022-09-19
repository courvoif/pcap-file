use std::io::Read;

use crate::errors::*;
use crate::pcap::{PcapHeader, PcapPacket};
use crate::read_buffer::ReadBuffer;
use crate::PcapParser;


/// Reads a pcap from a reader.
///
/// It implements the Iterator trait in order to read one packet at a time
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcap::PcapReader;
///
/// let file_in = File::open("test.pcap").expect("Error opening file");
/// let mut pcap_reader = PcapReader::new(file_in).unwrap();
///
/// // Read test.pcap
/// while let Some(pkt) = pcap_reader.next_packet() {
///     //Check if there is no error
///     let pkt = pkt.unwrap();
///
///     //Do something
/// }
/// ```
#[derive(Debug)]
pub struct PcapReader<R: Read> {
    parser: PcapParser,
    reader: ReadBuffer<R>,
}

impl<R: Read> PcapReader<R> {
    /// Create a new PcapReader from an existing reader.
    /// This function read the global pcap header of the file to verify its integrity.
    ///
    /// The underlying reader must point to a valid pcap file/stream.
    ///
    /// # Errors
    /// Return an error if the data stream is not in a valid pcap file format.
    /// Or if the underlying data are not readable.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::fs::File;
    ///
    /// use pcap_file::pcap::PcapReader;
    ///
    /// let file_in = File::open("test.pcap").expect("Error opening file");
    /// let pcap_reader = PcapReader::new(file_in).unwrap();
    /// ```
    pub fn new(reader: R) -> Result<PcapReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = unsafe { reader.parse_with(PcapParser::new)? };

        Ok(PcapReader { parser, reader })
    }

    /// Consumes the `PcapReader`, returning the wrapped reader.
    pub fn into_reader(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the next packet
    pub fn next_packet(&mut self) -> Option<Result<PcapPacket, PcapError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    Some(unsafe { self.reader.parse_with(|src| self.parser.next_packet(src)) })
                }
                else {
                    None
                }
            },
            Err(e) => Some(Err(e.into())),
        }
    }

    /// Returns the global header of the pcap
    pub fn header(&self) -> PcapHeader {
        self.parser.header()
    }
}
