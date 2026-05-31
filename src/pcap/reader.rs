use std::io::Read;

use super::{PcapParser, RawPcapPacket};
use crate::pcap::{PcapHeader, PcapPacket, PcapReadError};
use crate::read_buffer::ReadBuffer;

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
}

impl<R: Read> PcapReader<R> {
    /// Creates a new [`PcapReader`] from an existing reader.
    ///
    /// This function reads the global pcap header of the file to verify its integrity.
    ///
    /// The underlying reader must point to a valid pcap file/stream.
    ///
    /// # Errors
    /// The data stream is not in a valid pcap file format.
    ///
    /// The underlying data are not readable.
    pub fn new(reader: R) -> Result<PcapReader<R>, PcapReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapParser::new)?;

        Ok(PcapReader { parser, reader })
    }

    /// Creates a new [`PcapReader`] with a custom internal buffer capacity.
    ///
    /// Use this when the stream can contain packets larger than the default
    /// reader buffer.
    ///
    /// # Errors
    /// The data stream is not in a valid pcap file format.
    ///
    /// The underlying data are not readable.
    pub fn with_capacity(reader: R, capacity: usize) -> Result<PcapReader<R>, PcapReadError> {
        let mut reader = ReadBuffer::with_capacity(reader, capacity);
        let parser = reader.parse_with(PcapParser::new)?;

        Ok(PcapReader { parser, reader })
    }

    /// Consumes the [`PcapReader`], returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the next [`PcapPacket`].
    /// [`None`] means that the reader has reached the EoF.
    /// Won't advance the reader past any malformed packets.
    ///
    /// # Errors
    /// - Some variants of [`PcapReadError::Io`] can be retried.
    /// - Other variants can be retried using [`Self::next_raw_packet`] to parse the faulty packet.
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
    /// [`None`] means that the reader has reached the EoF.
    ///
    /// More permissive than [`Self::next_packet`], can be used to parse malformed files.
    ///
    /// A [`RawPcapPacket`] can be validated using [`RawPcapPacket::try_into_pcap_packet`].
    ///
    /// # Errors
    /// - Only [`PcapReadError::Io`] can happen, some of its variants can be retried.
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
    type IntoIter = PcapReaderIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        PcapReaderIterator {
            reader: self,
            err: false,
        }
    }
}

/// Iterator over owned [`PcapPacket`] values.
///
/// This is slower than [`PcapReader::next_packet`] because each packet payload
/// is copied out of the internal read buffer.
///
/// Stops after the first error.
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
/// for pkt in pcap_reader {
///     let pkt = pkt.unwrap();
///
///     //Do something
/// }
/// ```
#[derive(Debug)]
pub struct PcapReaderIterator<R: Read> {
    reader: PcapReader<R>,
    err: bool,
}

impl<R: Read> PcapReaderIterator<R> {
    /// Gets a reference to the wrapped [`PcapReader`].
    pub fn get_ref(&self) -> &PcapReader<R> {
        &self.reader
    }

    /// Consumes the iterator, returning the wrapped [`PcapReader`].
    pub fn into_inner(self) -> PcapReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for PcapReaderIterator<R> {
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
