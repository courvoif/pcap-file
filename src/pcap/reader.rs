//! Streaming pcap reader and packet iterator.

/* ----- Imports ----- */

use std::io::Read;

use super::{PcapParser, RawPcapPacket};
use crate::pcap::{PcapHeader, PcapPacket, PcapReadError, PcapReadErrorKind};
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
    /// Parser initialized from the global header.
    parser: PcapParser,
    /// Buffered input and the number of consumed bytes.
    reader: ReadBuffer<R>,
    /// Whether a fatal error prevents further reading.
    poisoned: bool,
    /// Number of consumed packets, including packets rejected during validation.
    packets_read: u64,
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
        let parser = reader
            .parse_with(PcapParser::new)
            .map_err(|kind| PcapReadError::new(0, 0, kind))?;

        Ok(PcapReader {
            parser,
            reader,
            poisoned: false,
            packets_read: 0,
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
        let parser = reader
            .parse_with(PcapParser::new)
            .map_err(|kind| PcapReadError::new(0, 0, kind))?;

        Ok(PcapReader {
            parser,
            reader,
            poisoned: false,
            packets_read: 0,
        })
    }

    /// Returns the next validated [`PcapPacket`].
    ///
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error and the reader remains poisoned.
    ///
    /// # Errors
    /// - Includes the packet number and its starting byte offset
    /// - On [`PcapReadErrorKind::Validation`], the packet is skipped.
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error is returned once. Later calls return [`None`].
    #[must_use = "the result contains either the next packet or a read error"]
    pub fn next_packet<'a>(&'a mut self) -> Option<Result<PcapPacket<'a>, PcapReadError>> {
        if self.poisoned {
            return None;
        }

        let packet_number = self.packets_read;
        let offset = self.reader.bytes_used;

        let res = match self.reader.has_data_left() {
            Ok(true) => {
                let res: Result<RawPcapPacket<'_>, PcapReadErrorKind> = self
                    .reader
                    .parse_with(|src| self.parser.next_raw_packet(src))
                    .inspect(|_| self.packets_read += 1);

                res.and_then(|raw_packet| {
                    raw_packet
                        .try_into_pcap_packet(self.parser.header().ts_resolution, self.parser.header().snaplen)
                        .map_err(PcapReadErrorKind::from)
                })
            }
            Ok(false) => return None,
            Err(error) => Err(PcapReadErrorKind::Io(error)),
        }
        .map_err(|kind| PcapReadError::new(packet_number, offset, kind))
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Returns the next [`RawPcapPacket`].
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error and the reader remains poisoned.
    ///
    /// Use this when you need raw timestamp and length fields, including fields
    /// from packets that fail semantic validation.
    /// Call [`RawPcapPacket::try_into_pcap_packet`] to validate and convert it.
    ///
    /// # Errors
    /// - Errors include the packet number and its starting byte offset.
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error is returned once. Later calls return [`None`].
    #[must_use = "the result contains either the next raw packet or a read error"]
    pub fn next_raw_packet<'a>(&'a mut self) -> Option<Result<RawPcapPacket<'a>, PcapReadError>> {
        if self.poisoned {
            return None;
        }

        let packet_number = self.packets_read;
        let offset = self.reader.bytes_used;

        let res = match self.reader.has_data_left() {
            Ok(true) => self
                .reader
                .parse_with(|src| self.parser.next_raw_packet(src))
                .inspect(|_| self.packets_read += 1),
            Ok(false) => return None,
            Err(error) => Err(PcapReadErrorKind::Io(error)),
        }
        .map_err(|kind| PcapReadError::new(packet_number, offset, kind))
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Allows reading again after a fatal error.
    /// This keeps the buffered bytes and pcap header unchanged.
    ///
    /// # Safety
    /// The caller must ensure the unread bytes and underlying input can be read
    /// as packets under the current header.
    /// Otherwise later reads may repeat the error or interpret data incorrectly.
    pub unsafe fn reset_poisoned(&mut self) {
        self.poisoned = false;
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
/// - On [`PcapReadErrorKind::Validation`], the error is returned and the packet is skipped.
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
