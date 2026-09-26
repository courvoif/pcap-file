/* ----- Imports ----- */

use std::io::Read;

use super::blocks::block_common::{Block, RawBlock};
use super::{PcapNgPacket, PcapNgParser, PcapNgState};
use crate::pcapng::errors::{BlockError, BlockValidationError, PacketConversionError, PcapNgReadError};
use crate::read_buffer::ReadBuffer;

/* ----- Reader ----- */

/// Reads a PcapNg from a reader.
///
/// # Example
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let mut pcapng_reader = PcapNgReader::new(file_in, true).unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block() {
///     //Check if there is no error
///     let (block, state) = block.unwrap();
///
///     //Do something
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgReader<R: Read> {
    parser: PcapNgParser,
    reader: ReadBuffer<R>,
    poisoned: bool,
}

impl<R: Read> PcapNgReader<R> {
    /// Creates a [`PcapNgReader`] from a reader.
    /// The input must start with a valid pcapng capture.
    ///
    /// Set `strict` to `true` to validate blocks returned by
    /// [`Self::next_block`].
    /// Section Header and Interface Description blocks must be valid in either
    /// mode.
    ///
    /// # Errors
    /// - The capture does not start with a valid Section Header Block.
    /// - The input cannot be read.
    pub fn new(reader: R, strict: bool) -> Result<Self, PcapNgReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(|src| PcapNgParser::new(src, strict))?;
        Ok(Self {
            parser,
            reader,
            poisoned: false,
        })
    }

    /// Creates a [`PcapNgReader`] with a custom capacity.
    ///
    /// Set `capacity` large enough for the largest block you expect to read.
    ///
    /// Set `strict` as in [`Self::new`].
    ///
    /// # Errors
    /// - The capture does not start with a valid Section Header Block.
    /// - The input cannot be read.
    pub fn with_capacity(reader: R, capacity: usize, strict: bool) -> Result<Self, PcapNgReadError> {
        let mut reader = ReadBuffer::with_capacity(reader, capacity);
        let parser = reader.parse_with(|src| PcapNgParser::new(src, strict))?;
        Ok(Self {
            parser,
            reader,
            poisoned: false,
        })
    }

    /// Returns the next [`Block`] and the [`PcapNgState`].
    ///
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error.
    ///
    /// Use this when you need typed block data.
    ///
    /// The `strict` setting controls validation of blocks.
    /// Section Header and Interface Description blocks must be valid in either
    /// mode.
    ///
    /// # Errors
    /// - On [`PcapNgReadError::Block`], the block is skipped.
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error poisons the reader. Later calls return [`None`].
    #[must_use = "the result contains either the next block or a read error"]
    pub fn next_block<'a>(&'a mut self) -> Option<Result<(Block<'a>, &'a PcapNgState), PcapNgReadError>> {
        if self.poisoned {
            return None;
        }

        let res = match self.reader.has_data_left() {
            Ok(true) => {
                let res: Result<RawBlock<'_>, PcapNgReadError> =
                    self.reader.parse_with(|src| self.parser.next_raw_block(src));
                // # SAFETY
                // The raw block borrows only from the reader's internal buffer.
                // The returned lifetime is tied to `&'a mut self`, which prevents that buffer from being mutated.
                let res: Result<RawBlock<'a>, PcapNgReadError> = unsafe { std::mem::transmute(res) };

                res.and_then(|raw_block| {
                    let block = raw_block.try_into_block(&self.parser.state)?;

                    if self.parser.strict() {
                        block.validate(&self.parser.state)?;
                    }

                    Ok((block, &self.parser.state))
                })
            }
            Ok(false) => return None,
            Err(e) => Err(PcapNgReadError::Io(e)),
        }
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Returns the next [`RawBlock`] and the [`PcapNgState`].
    ///
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error.
    ///
    /// Use this when you need raw block data or want to parse an unsupported
    /// block type.
    ///
    /// Use the returned state with [`RawBlock::try_into_block`] to decode a
    /// block, then with [`Block::validate`] to check it semantically.
    /// Section Header and Interface Description blocks must be valid to read
    /// later blocks.
    ///
    /// # Errors
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error poisons the reader. Later calls return [`None`].
    #[must_use = "the result contains either the next raw block or a read error"]
    pub fn next_raw_block<'a>(&'a mut self) -> Option<Result<(RawBlock<'a>, &'a PcapNgState), PcapNgReadError>> {
        if self.poisoned {
            return None;
        }

        let res = match self.reader.has_data_left() {
            Ok(true) => {
                let res: Result<RawBlock<'_>, PcapNgReadError> =
                    self.reader.parse_with(|src| self.parser.next_raw_block(src));
                // # SAFETY
                // The raw block borrows only from the reader's internal buffer.
                // The returned lifetime is tied to `&'a mut self`, which prevents that buffer from being mutated.
                let res: Result<RawBlock<'a>, PcapNgReadError> = unsafe { std::mem::transmute(res) };

                res.map(|blk| (blk, &self.parser.state))
            }
            Ok(false) => return None,
            Err(e) => Err(PcapNgReadError::Io(e)),
        }
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Returns whether this reader and its packet iterator validate blocks.
    ///
    /// Section Header and Interface Description blocks are always validated.
    pub fn strict(&self) -> bool {
        self.parser.strict()
    }

    /// Returns the current [`PcapNgState`].
    pub fn state(&self) -> &PcapNgState {
        self.parser.state()
    }

    /// Consumes the reader and returns an iterator over owned packets.
    ///
    /// Non-packet blocks are skipped. Non-fatal errors are yielded without
    /// stopping the iterator; polling it again continues reading.
    /// A fatal error is yielded once, then iteration ends.
    pub fn packets(self) -> PcapNgPacketIterator<R> {
        PcapNgPacketIterator { reader: self }
    }

    /// Consumes the [`Self`], returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Gets a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        self.reader.get_ref()
    }

    /// Returns the number of bytes parsed so far.
    pub fn bytes_parsed(&self) -> u64 {
        self.reader.bytes_used
    }
}

/* ----- Packet iteration ----- */

/// Returns an iterator over owned packets and skips non-packet blocks.
///
/// Use this to read packets from packet related Blocks.
///
/// # Errors
/// - On [`PcapNgReadError::Block`], , the error is returned and the block is skipped.
/// - Retry a non-fatal I/O error by polling the iterator again.
/// - A fatal error is yielded once. Later polls return [`None`].
///
/// # Example
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let pcapng_reader = PcapNgReader::new(file_in, true).unwrap();
///
/// for packet in pcapng_reader.packets() {
///     let packet = packet.unwrap();
///
///     //Do something
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgPacketIterator<R: Read> {
    reader: PcapNgReader<R>,
}

impl<R: Read> PcapNgPacketIterator<R> {
    /// Gets a reference to the wrapped [`PcapNgReader`].
    pub fn get_ref(&self) -> &PcapNgReader<R> {
        &self.reader
    }

    /// Consumes the iterator, returning the wrapped [`PcapNgReader`].
    pub fn into_inner(self) -> PcapNgReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for PcapNgPacketIterator<R> {
    type Item = Result<PcapNgPacket<'static>, PcapNgReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.reader.next_block() {
                Some(Ok((block, state))) => {
                    let type_ = block.type_code();
                    match PcapNgPacket::from_block(block, state) {
                        Ok(packet) => return Some(Ok(packet.into_owned())),
                        Err(PacketConversionError::NotPacket(_)) => continue,
                        Err(PacketConversionError::InvalidInterfaceId(id)) => {
                            return Some(Err(BlockError {
                                type_,
                                source: Box::new(BlockValidationError::InvalidInterfaceId(id)),
                            }
                            .into()));
                        }
                    }
                }
                Some(Err(error)) => return Some(Err(error)),
                None => return None,
            }
        }
    }
}
