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
/// let pcap = vec![0_u8; 0];
/// let mut src = &pcap[..];
///
/// // Creates a new parser and parse the pcap header
/// let (rem, pcap_parser) = PcapParser::new(&pcap[..]).unwrap();
/// src = rem;
///
/// loop {
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
///         Err(PcapParseError::IncompleteBuffer(_,_)) => {}, // Load more data into src
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
    /// Creates a new [`PcapParser`].
    ///
    /// Returns the remainder and the parser.
    pub fn new(slice: &[u8]) -> Result<(&[u8], PcapParser), PcapParseError> {
        let (slice, header) = PcapHeader::from_slice(slice)?;
        let parser = PcapParser { header };
        Ok((slice, parser))
    }

    /// Returns the remainder and the next [`PcapPacket`].
    /// 
    /// # Errors
    /// - [`PcapParseError::IncompleteBuffer`] is recoverable (by loading more data).
    /// - Other errors will prevent the parser from advancing further.
    ///   Some can be recovered by calling [`PcapParser::next_raw_packet`].
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

    /// Returns the remainder and the next [`RawPcapPacket`].
    /// 
    /// More permissive than [`Self::next_packet`], can be used to parse malformed files.
    /// 
    /// A [`RawPcapPacket`] can be validated using [`RawPcapPacket::try_into_pcap_packet`].
    /// 
    /// # Errors
    /// - Only [`PcapError::IncompleteBuffer`] can happen. It is recoverable by loading more data.
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
