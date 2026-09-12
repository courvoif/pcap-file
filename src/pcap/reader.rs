use std::io::Read;

use super::{PcapParser, RawPcapPacket};
use crate::pcap::{PcapHeader, PcapPacket, PcapReadError};
use crate::read_buffer::ReadBuffer;

/// Reads a pcap from a reader.
///
/// Buffers data from the underlying reader internally.
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
///     let pkt = pkt.unwrap();
///
///     // Process the packet.
/// }
/// ```
#[derive(Debug)]
pub struct PcapReader<R: Read> {
    parser: PcapParser,
    reader: ReadBuffer<R>,
}

impl<R: Read> PcapReader<R> {
    /// Creates a new [`PcapReader`] from an existing reader.
    ///
    /// This function reads the global pcap header of the file to verify its integrity.
    ///
    /// Prefer an unbuffered input because this type already uses an internal
    /// buffer with a default capacity of 8 MB.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapReadError::Io`] if the underlying reader cannot be read.
    /// - Returns [`PcapReadError::Validation`] if the input does not start with
    ///   a valid pcap header.
    pub fn new(reader: R) -> Result<PcapReader<R>, PcapReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapParser::new)?;

        Ok(PcapReader { parser, reader })
    }

    /// Creates a new [`PcapReader`] with a custom internal buffer capacity.
    ///
    /// Use this when the stream can contain packets larger than the default
    /// internal buffer capacity of 8 MB.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapReadError::Io`] if the underlying reader cannot be read.
    /// - Returns [`PcapReadError::Validation`] if the input does not start with
    ///   a valid pcap header.
    pub fn with_capacity(reader: R, capacity: usize) -> Result<PcapReader<R>, PcapReadError> {
        let mut reader = ReadBuffer::with_capacity(reader, capacity);
        let parser = reader.parse_with(PcapParser::new)?;

        Ok(PcapReader { parser, reader })
    }

    /// Consumes the [`PcapReader`], returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Returns a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        self.reader.get_ref()
    }

    /// Returns the number of bytes parsed so far.
    pub fn bytes_parsed(&self) -> u64 {
        self.reader.bytes_used
    }

    /// Returns the next [`PcapPacket`].
    ///
    /// Returns [`None`] after reaching EOF.
    ///
    /// # Errors
    ///
    /// - Returns an error if the input cannot be read, the next packet is
    ///   incomplete, or its typed content is malformed.
    /// - Transient I/O errors may be retried by calling this method again.
    /// - All other errors are terminal for this reader. After receiving one,
    ///   callers should discard the reader. Use [`Self::next_raw_packet`] from
    ///   the beginning when malformed packet content must be handled.
    pub fn next_packet(&mut self) -> Option<Result<PcapPacket<'_>, PcapReadError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with(|src| self.parser.next_packet(src)))
                } else {
                    None
                }
            }
            Err(e) => Some(Err(PcapReadError::Io(e))),
        }
    }

    /// Returns the next [`RawPcapPacket`].
    ///
    /// Returns [`None`] after reaching EOF.
    ///
    /// This is the permissive API for handling packets whose typed content
    /// may be malformed.
    ///
    /// A [`RawPcapPacket`] can be validated using [`RawPcapPacket::try_into_pcap_packet`].
    ///
    /// # Errors
    ///
    /// - Returns an error if the input cannot be read or the next packet is
    ///   incomplete or too large for the internal buffer.
    /// - Transient I/O errors may be retried by calling this method again.
    /// - All other errors are terminal for this reader. After receiving one,
    ///   callers should discard the reader.
    pub fn next_raw_packet(&mut self) -> Option<Result<RawPcapPacket<'_>, PcapReadError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with(|src| self.parser.next_raw_packet(src)))
                } else {
                    None
                }
            }
            Err(e) => Some(Err(PcapReadError::Io(e))),
        }
    }

    /// Returns the global header of the pcap.
    pub fn header(&self) -> PcapHeader {
        self.parser.header()
    }
}

impl<R: Read> IntoIterator for PcapReader<R> {
    type Item = Result<PcapPacket<'static>, PcapReadError>;
    type IntoIter = PcapPacketIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        PcapPacketIterator {
            reader: self,
            err: false,
        }
    }
}

/// Iterator over owned [`PcapPacket`] values.
///
/// This iterator copies each packet's data out of the internal read buffer, so
/// it is slower than [`PcapReader::next_packet`]. It stops after the first
/// error.
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcap::PcapReader;
///
/// let file_in = File::open("test.pcap").expect("Error opening file");
/// let pcap_reader = PcapReader::new(file_in).unwrap();
///
/// for pkt in pcap_reader {
///     let pkt = pkt.unwrap();
///
///     // Process the packet.
/// }
/// ```
#[derive(Debug)]
pub struct PcapPacketIterator<R: Read> {
    reader: PcapReader<R>,
    err: bool,
}

impl<R: Read> PcapPacketIterator<R> {
    /// Returns a reference to the underlying [`PcapReader`].
    pub fn get_ref(&self) -> &PcapReader<R> {
        &self.reader
    }

    /// Consumes the iterator, returning the underlying [`PcapReader`].
    pub fn into_inner(self) -> PcapReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for PcapPacketIterator<R> {
    type Item = Result<PcapPacket<'static>, PcapReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.err {
            return None;
        }

        let packet = self
            .reader
            .next_packet()
            .map(|packet| packet.map(PcapPacket::into_owned));

        if matches!(packet, Some(Err(_))) {
            self.err = true;
        }

        packet
    }
}
