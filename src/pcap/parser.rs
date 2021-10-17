use byteorder::{BigEndian, LittleEndian};

use crate::{
    Endianness,
    errors::*,
    pcap::Packet,
    pcap::PcapHeader
};


/// Parser for a Pcap formated stream.
///
/// # Examples
///
/// ```no_run
/// use pcap_file::pcap::PcapParser;
/// use pcap_file::PcapError;
///
/// let pcap = vec![0_u8; 0];
/// let mut src = &pcap[..];
///
/// // Creates a new parser and parse the pcap header
/// let (rem, pcap_parser) = PcapParser::new(&pcap[..]).unwrap();
/// src = rem;
///
/// loop {
///
///     match pcap_parser.next_packet(src) {
///         Ok((rem, packet)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///
///             // No more data, if no more incoming either then this is the end of the file
///             if rem.is_empty() {
///                 break;
///             }
///         },
///         Err(PcapError::IncompleteBuffer(needed)) => {},// Load more data into src
///         Err(_) => {}// Parsing error
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PcapParser {
    header: PcapHeader
}

impl PcapParser {

    /// Creates a new `PcapParser`.
    /// Returns the parser and the remainder.
    pub fn new(slice: &[u8]) -> ResultParsing<(&[u8], PcapParser)> {

        let (slice, header) = PcapHeader::from_slice(slice)?;

        let parser = PcapParser {
            header
        };

        Ok((slice, parser))
    }

    /// Returns the next packet and the remainder.
    pub fn next_packet<'a>(&self, slice: &'a[u8]) -> ResultParsing<(&'a [u8], Packet<'a>)> {

        let ts_resolution = self.header.ts_resolution();

        match self.header.endianness() {
            Endianness::Big => Packet::from_slice::<BigEndian>(slice, ts_resolution),
            Endianness::Little => Packet::from_slice::<LittleEndian>(slice, ts_resolution)
        }
    }

    pub fn header(&self) -> PcapHeader {
        self.header
    }
}
