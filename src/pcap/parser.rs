use byteorder_slice::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::Endianness;
use crate::pcap::PcapHeader;
use crate::pcap::PcapPacket;
use crate::pcap::PcapParseError;

/// Parses a pcap stream from a byte slice.
///
/// Match [`PcapParseError::IncompleteBuffer`] to determine whether more data is needed.
///
/// # Example
/// ```no_run
/// use pcap_file::pcap::{PcapParseError, PcapParser};
///
/// let pcap = std::fs::read("test.pcap").expect("Error reading file");
/// let mut src = &pcap[..];
///
/// // Create a parser and parse the pcap header.
/// let (rem, pcap_parser) = PcapParser::new(&pcap[..]).unwrap();
/// src = rem;
///
/// while !src.is_empty() {
///     match pcap_parser.next_packet(src) {
///         Ok((rem, packet)) => {
///             // Process the packet.
///
///             // Advance to the remaining input.
///             src = rem;
///
///         },
///         Err(PcapParseError::IncompleteBuffer(_,_)) => {
///             // Load more data into src if parsing a stream.
///         },
///         Err(_) => {
///             // Handle an unrecoverable parsing error.
///         },
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PcapParser {
    header: PcapHeader,
}

impl PcapParser {
    /// Creates a new [`PcapParser`].
    ///
    /// Returns the remainder and the parser.
    ///
    /// # Errors
    ///
    /// - Returns any error produced by [`PcapHeader::from_slice`].
    pub fn new(slice: &[u8]) -> Result<(&[u8], PcapParser), PcapParseError> {
        let (slice, header) = PcapHeader::from_slice(slice)?;
        let parser = PcapParser { header };
        Ok((slice, parser))
    }

    /// Returns the remainder and the next [`PcapPacket`].
    ///
    /// # Errors
    /// - Returns [`PcapParseError::IncompleteBuffer`] if the input does not
    ///   contain a complete packet. Load more data and retry with the same input.
    /// - Returns [`PcapParseError::Validation`] if a packet field is invalid.
    ///   The input remains unconsumed and can be passed to
    ///   [`PcapParser::next_raw_packet`].
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
                .map_err(|error| PcapParseError::Validation(error.source))
        })
    }

    /// Returns the remainder and the next [`RawPcapPacket`].
    ///
    /// This method is more permissive than [`Self::next_packet`] and can parse malformed packets.
    ///
    /// A [`RawPcapPacket`] can be validated using [`RawPcapPacket::try_into_pcap_packet`].
    ///
    /// # Errors
    ///
    /// - Returns [`PcapParseError::IncompleteBuffer`] if the input does not
    ///   contain a complete packet. Load more data and retry with the same input.
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
