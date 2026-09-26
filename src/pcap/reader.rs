use std::io::Read;

use super::{PcapParser, RawPcapPacket};
use crate::pcap::{PcapHeader, PcapPacket, PcapReadError};
use crate::read_buffer::ReadBuffer;

/* ----- Reader ----- */

/// Reads a pcap from a reader.
///
/// # Example
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
    poisoned: bool,
}

impl<R: Read> PcapReader<R> {
    /// Creates a [`PcapReader`] from a reader.
    /// The reader must start with a valid pcap capture.
    ///
    /// # Errors
    /// - The data stream is not in a valid pcap file format.
    /// - The underlying data are not readable.
    pub fn new(reader: R) -> Result<PcapReader<R>, PcapReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapParser::new)?;

        Ok(PcapReader {
            parser,
            reader,
            poisoned: false,
        })
    }

    /// Creates a [`PcapReader`] with a custom capacity.
    ///
    /// Set `capacity` large enough for the largest packet you expect to read.
    ///
    /// # Errors
    /// - The data stream is not in a valid pcap file format.
    /// - The underlying data are not readable.
    pub fn with_capacity(reader: R, capacity: usize) -> Result<PcapReader<R>, PcapReadError> {
        let mut reader = ReadBuffer::with_capacity(reader, capacity);
        let parser = reader.parse_with(PcapParser::new)?;

        Ok(PcapReader {
            parser,
            reader,
            poisoned: false,
        })
    }

    /// Returns the next validated [`PcapPacket`].
    ///
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error.
    ///
    /// # Errors
    /// - On [`PcapReadError::Validation`], the packet is skipped.
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error is returned once. Later calls return [`None`].
    #[must_use = "the result contains either the next packet or a read error"]
    pub fn next_packet<'a>(&'a mut self) -> Option<Result<PcapPacket<'a>, PcapReadError>> {
        if self.poisoned {
            return None;
        }

        let res = match self.reader.has_data_left() {
            Ok(true) => {
                let res: Result<RawPcapPacket<'_>, PcapReadError> =
                    self.reader.parse_with(|src| self.parser.next_raw_packet(src));

                res.and_then(|raw_packet| {
                    raw_packet
                        .try_into_pcap_packet(self.parser.header().ts_resolution, self.parser.header().snaplen)
                        .map_err(PcapReadError::from)
                })
            }
            Ok(false) => return None,
            Err(error) => Err(PcapReadError::Io(error)),
        }
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Returns the next [`RawPcapPacket`].
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error.
    ///
    /// Use this when you need raw timestamp and length fields, including fields
    /// from packets that fail semantic validation.
    /// Call [`RawPcapPacket::try_into_pcap_packet`] to validate and convert it.
    ///
    /// # Errors
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error is returned once. Later calls return [`None`].
    #[must_use = "the result contains either the next raw packet or a read error"]
    pub fn next_raw_packet<'a>(&'a mut self) -> Option<Result<RawPcapPacket<'a>, PcapReadError>> {
        if self.poisoned {
            return None;
        }

        let res = match self.reader.has_data_left() {
            Ok(true) => self.reader.parse_with(|src| self.parser.next_raw_packet(src)),
            Ok(false) => return None,
            Err(error) => Err(PcapReadError::Io(error)),
        }
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Returns the pcap global header.
    pub fn header(&self) -> PcapHeader {
        self.parser.header()
    }

    /// Consumes the reader and returns an iterator over owned packets.
    ///
    /// Non-fatal errors are yielded without stopping the iterator. A fatal
    /// error is yielded once, then iteration ends.
    pub fn packets(self) -> PcapPacketIterator<R> {
        PcapPacketIterator { reader: self }
    }

    /// Gets a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        self.reader.get_ref()
    }

    /// Consumes the [`PcapReader`], returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the number of bytes parsed so far.
    pub fn bytes_parsed(&self) -> u64 {
        self.reader.bytes_used
    }
}

/* ----- Packet iteration ----- */

/// Returns an iterator over owned [`PcapPacket`] values.
///
/// # Errors
/// - On [`PcapReadError::Validation`], the error is returned and the packet is skipped.
/// - Retry a non-fatal I/O error by polling the iterator again.
/// - A fatal error is yielded once. Later polls return [`None`].
///
/// # Example
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcap::PcapReader;
///
/// let file_in = File::open("test.pcap").expect("Error opening file");
/// let pcap_reader = PcapReader::new(file_in).unwrap();
///
/// for pkt in pcap_reader.packets() {
///     let pkt = pkt.unwrap();
///
///     //Do something
/// }
/// ```
#[derive(Debug)]
pub struct PcapPacketIterator<R: Read> {
    reader: PcapReader<R>,
}

impl<R: Read> PcapPacketIterator<R> {
    /// Gets a reference to the wrapped [`PcapReader`].
    pub fn get_ref(&self) -> &PcapReader<R> {
        &self.reader
    }

    /// Consumes the iterator, returning the wrapped [`PcapReader`].
    pub fn into_inner(self) -> PcapReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for PcapPacketIterator<R> {
    type Item = Result<PcapPacket<'static>, PcapReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader
            .next_packet()
            .map(|packet| packet.map(PcapPacket::into_owned))
    }
}
