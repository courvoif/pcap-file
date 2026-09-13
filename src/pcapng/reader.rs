//! Buffered pcapng stream reading and packet iteration.

use std::io::Read;

use super::blocks::block_common::{Block, RawBlock};
use super::{PcapNgPacket, PcapNgPacketOrBlock, PcapNgParser, PcapNgState};
use crate::pcapng::errors::PcapNgReadError;
use crate::read_buffer::ReadBuffer;

/// Reads a pcapng stream from a reader.
///
/// Buffers data from the underlying reader internally.
///
/// Use [`Self::state`] to access the current section and interfaces.
///
/// # Examples
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block() {
///     let (block, state) = block.unwrap();
///
///     // Process the block using its state.
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgReader<R: Read> {
    parser: PcapNgParser,
    reader: ReadBuffer<R>,
}

impl<R: Read> PcapNgReader<R> {
    /// Creates a new [`PcapNgReader`] from an existing reader.
    ///
    /// Parses the first block, which must be a valid
    /// [`SectionHeaderBlock`](crate::pcapng::blocks::section_header::SectionHeaderBlock).
    ///
    /// Prefer an unbuffered input because this type already uses an internal
    /// buffer with a default capacity of 8 MB.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapNgReadError::Io`] if the underlying reader cannot be read.
    /// - Returns an error if the input does not start with a valid Section
    ///   Header Block.
    pub fn new(reader: R) -> Result<PcapNgReader<R>, PcapNgReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapNgParser::new)?;
        Ok(Self { parser, reader })
    }

    /// Creates a new [`PcapNgReader`] with a custom internal buffer capacity.
    ///
    /// Parses the first block, which must be a valid
    /// [`SectionHeaderBlock`](crate::pcapng::blocks::section_header::SectionHeaderBlock).
    ///
    /// Use this when the stream can contain blocks larger than the default
    /// internal buffer capacity of 8 MB.
    ///
    /// # Errors
    ///
    /// - Returns [`PcapNgReadError::Io`] if the underlying reader cannot be read.
    /// - Returns an error if the input does not start with a valid Section
    ///   Header Block.
    pub fn with_capacity(reader: R, capacity: usize) -> Result<PcapNgReader<R>, PcapNgReadError> {
        let mut reader = ReadBuffer::with_capacity(reader, capacity);
        let parser = reader.parse_with(PcapNgParser::new)?;
        Ok(Self { parser, reader })
    }

    /// Returns the next [`Block`] and the current [`PcapNgState`].
    ///
    /// Returns [`None`] after reaching EOF.
    ///
    /// The returned state already includes the effects of the returned block.
    /// Use this method instead of the owned iterator when processing a block
    /// requires state such as its section or interface descriptions.
    ///
    /// # Errors
    ///
    /// - Returns an error if the input cannot be read, the next block is
    ///   incomplete or malformed, its typed content cannot be decoded,
    ///   or the pcapng state cannot be maintained.
    /// - Transient I/O errors may be retried by calling this method again.
    /// - All other errors are terminal for this reader. After receiving one,
    ///   callers should discard the reader. Use [`Self::next_raw_block`] from
    ///   the beginning when malformed block content must be handled.
    #[must_use = "in case of an error, ignoring this result may cause an infinite loop"]
    pub fn next_block<'a>(&'a mut self) -> Option<Result<(Block<'a>, &'a PcapNgState), PcapNgReadError>> {
        match self.reader.has_data_left() {
            Ok(true) => {
                // # SAFETY
                // Block must NOT contain a mutable reference to the state.
                // Keep the annotations to be sure that only the lifetime is transmuted.
                let result: Result<Block<'_>, PcapNgReadError> =
                    self.reader.parse_with(|src| self.parser.next_block(src));
                let result: Result<Block<'_>, PcapNgReadError> = unsafe { std::mem::transmute(result) };

                Some(result.map(|block| (block, &self.parser.state)))
            }
            Ok(false) => None,
            Err(error) => Some(Err(PcapNgReadError::Io(error))),
        }
    }

    /// Returns the next [`RawBlock`] and the current [`PcapNgState`].
    ///
    /// Returns [`None`] after reaching EOF.
    ///
    /// This is the permissive API for handling structurally valid blocks whose
    /// typed content may be malformed.
    ///
    /// A [`RawBlock`] can be validated using [`RawBlock::try_into_block`].
    ///
    /// # Errors
    ///
    /// - Returns an error if the input cannot be read, the next block is
    ///   incomplete or has invalid framing, or the pcapng state cannot be
    ///   maintained.
    /// - Transient I/O errors may be retried by calling this method again.
    /// - All other errors are terminal for this reader. After receiving an
    ///   error, callers should discard the reader.
    #[must_use = "in case of an error, ignoring this result may cause an infinite loop"]
    pub fn next_raw_block<'a>(&'a mut self) -> Option<Result<(RawBlock<'a>, &'a PcapNgState), PcapNgReadError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    // # SAFETY
                    // Block must NOT contain a mutable reference to the state.
                    // Keep the annotations to be sure that only the lifetime is transmuted.
                    let res: Result<RawBlock<'_>, PcapNgReadError> =
                        self.reader.parse_with(|src| self.parser.next_raw_block(src));
                    let res: Result<RawBlock<'_>, PcapNgReadError> = unsafe { std::mem::transmute(res) };

                    Some(res.map(|block| (block, &self.parser.state)))
                } else {
                    None
                }
            }
            Err(error) => Some(Err(PcapNgReadError::Io(error))),
        }
    }

    /// Returns the current [`PcapNgState`].
    ///
    /// Use the state to access the current section, interfaces, endianness, and
    /// timestamp conversion methods.
    pub fn state(&self) -> &PcapNgState {
        self.parser.state()
    }

    /// Consumes the [`PcapNgReader`], returning the underlying reader.
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
}

impl<R: Read> IntoIterator for PcapNgReader<R> {
    type Item = Result<PcapNgPacket<'static>, PcapNgReadError>;
    type IntoIter = PcapNgPacketIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        PcapNgPacketIterator {
            reader: self,
            err: false,
        }
    }
}

/* ----- PcapNgPacketIterator ----- */

/// Iterator over owned [`PcapNgPacket`] values.
///
/// This iterator is intended for simple packet traversal. It skips non-packet
/// blocks, returns owned packets, does not expose the evolving [`PcapNgState`],
/// and stops after the first error.
///
/// Use [`PcapNgReader::next_block`] when processing a block requires its
/// corresponding state, and [`PcapNgReader::next_raw_block`] when malformed
/// block content must be handled.
///
/// # Examples
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// for packet in pcapng_reader {
///     let packet = packet.unwrap();
///
///     // Process the packet.
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgPacketIterator<R: Read> {
    reader: PcapNgReader<R>,
    err: bool,
}

impl<R: Read> PcapNgPacketIterator<R> {
    /// Returns a reference to the underlying [`PcapNgReader`].
    pub fn get_ref(&self) -> &PcapNgReader<R> {
        &self.reader
    }

    /// Consumes the iterator, returning the underlying [`PcapNgReader`].
    pub fn into_inner(self) -> PcapNgReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for PcapNgPacketIterator<R> {
    type Item = Result<PcapNgPacket<'static>, PcapNgReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.err {
            return None;
        }

        loop {
            match self.reader.next_block() {
                Some(Ok((block, _))) => {
                    if let PcapNgPacketOrBlock::Packet(packet) = block.into_pcapng_packet() {
                        return Some(Ok(packet.into_owned()));
                    }
                }
                Some(Err(error)) => {
                    self.err = true;
                    return Some(Err(error));
                }
                None => return None,
            }
        }
    }
}
