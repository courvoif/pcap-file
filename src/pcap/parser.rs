use byteorder_slice::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::Endianness;
use crate::pcap::PcapHeader;
use crate::pcap::PcapPacket;
use crate::pcap::PcapParseError;

/// Parses a Pcap from a slice of bytes.
///
/// You can match on [`PcapParseError::IncompleteBuffer`](crate::pcap::PcapParseError) to know if the parser needs more data.
///
/// # Example
/// ```no_run
/// use pcap_file::pcap::{PcapParseError, PcapParser};
///
/// let pcap = std::fs::read("test.pcap").expect("Error reading file");
/// let mut src = &pcap[..];
///
/// // Creates a new parser and parse the pcap header
/// let (rem, pcap_parser) = PcapParser::new(&pcap[..]).unwrap();
/// src = rem;
///
/// while !src.is_empty() {
///     match pcap_parser.next_packet(src) {
///         Ok((rem, packet)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///
///         },
///         Err(PcapParseError::IncompleteBuffer(_,_)) => {
///             // Load more data into src if parsing a stream.
///         },
///         Err(_) => {
///             // Parsing error, unrecoverable
///         },
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PcapParser {
    header: PcapHeader,
}

impl PcapParser {
    /// Creates a parser from the pcap global header and returns the remaining input.
    ///
    /// # Errors
    /// - On [`PcapParseError::IncompleteBuffer`], provide the rest of the
    ///   global header and call this method again.
    /// - On a validation error, provide a valid pcap global header.
    pub fn new(slice: &[u8]) -> Result<(&[u8], PcapParser), PcapParseError> {
        let (slice, header) = PcapHeader::from_slice(slice)?;
        let parser = PcapParser { header };
        Ok((slice, parser))
    }

    /// Returns the remaining input and the next validated [`PcapPacket`].
    ///
    /// # Errors
    /// - On [`PcapParseError::IncompleteBuffer`], provide more bytes and retry
    ///   with the same input.
    /// - On a validation error, call [`Self::next_raw_packet`] with the same
    ///   input to inspect the packet's raw fields.
    pub fn next_packet<'a>(&self, slice: &'a [u8]) -> Result<(&'a [u8], PcapPacket<'a>), PcapParseError> {
        let res = match self.header.endianness {
            Endianness::Big => RawPcapPacket::from_slice::<BigEndian>(slice),
            Endianness::Little => RawPcapPacket::from_slice::<LittleEndian>(slice),
        };

        let header = &self.header;
        res.and_then(|(rem, raw_pkt)| {
            raw_pkt
                .try_into_pcap_packet(header.ts_resolution, header.snaplen)
                .map(|pkt| (rem, pkt))
                .map_err(|e| e.into())
        })
    }

    /// Returns the remaining input and the next [`RawPcapPacket`].
    /// Use this when you need raw packet fields, including fields from a packet
    /// that fails semantic validation.
    ///
    /// Call [`RawPcapPacket::try_into_pcap_packet`] to validate and convert the
    /// raw packet.
    ///
    /// # Errors
    /// - On [`PcapParseError::IncompleteBuffer`], provide more bytes and retry
    ///   with the same input.
    pub fn next_raw_packet<'a>(&self, slice: &'a [u8]) -> Result<(&'a [u8], RawPcapPacket<'a>), PcapParseError> {
        match self.header.endianness {
            Endianness::Big => RawPcapPacket::from_slice::<BigEndian>(slice),
            Endianness::Little => RawPcapPacket::from_slice::<LittleEndian>(slice),
        }
    }

    /// Returns the header of the pcap file.
    pub fn header(&self) -> PcapHeader {
        self.header
    }
}
