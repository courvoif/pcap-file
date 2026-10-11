//! Streaming pcapng reader and packet iterator.

/* ----- Imports ----- */

use std::io::Read;

use super::blocks::block_common::{Block, RawBlock};
use super::{PcapNgPacket, PcapNgParser, PcapNgState};
use crate::pcapng::errors::{
    BlockError, BlockValidationError, PacketConversionError, PcapNgReadError, PcapNgReadErrorKind,
};
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
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let file = File::open("tests/pcapng/little_endian/basic/test001.pcapng")?;
///     let mut reader = PcapNgReader::new(file, true)?;
///
///     // Each returned record borrows the reader buffer until the next read.
///     while let Some(result) = reader.next_block() {
///         match result {
///             Ok((block, _state)) => println!("block type: {:#010x}", block.type_code()),
///             Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
///             Err(error) => return Err(error.into()),
///         }
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgReader<R: Read> {
    /// Parser and the current section and interface state.
    parser: PcapNgParser,
    /// Buffered input and the number of consumed bytes.
    reader: ReadBuffer<R>,
    /// Whether a fatal error prevents further reading.
    poisoned: bool,
    /// Number of consumed blocks, including Section Header Blocks and skipped blocks.
    blocks_read: u64,
}

impl<R: Read> PcapNgReader<R> {
    /// Creates a [`PcapNgReader`] from a reader.
    /// The input must start with a decodable Section Header Block.
    /// Uses a fixed buffer of `8_000_000` bytes; see [`Self::with_capacity`] for larger records.
    ///
    /// Set `strict` to `true` to validate the initial section header and typed blocks.
    /// With `false`, only decoding checks needed to maintain the state are applied.
    /// Typed decoding checks representations and individual options even when `strict` is false.
    ///
    /// # Errors
    /// - The initial Section Header Block cannot be decoded or fails strict validation.
    /// - The input cannot be read.
    pub fn new(reader: R, strict: bool) -> Result<Self, PcapNgReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader
            .parse_with(|src| PcapNgParser::new(src, strict))
            .map_err(|kind| PcapNgReadError::new(0, 0, kind))?;
        Ok(Self {
            parser,
            reader,
            poisoned: false,
            blocks_read: 1,
        })
    }

    /// Creates a [`PcapNgReader`] with a custom capacity.
    ///
    /// The buffer does not grow.
    /// A record exceeding its capacity produces a fatal I/O `UnexpectedEof` error.
    /// Include the full framing of every block, including the initial Section Header Block.
    ///
    /// Set `strict` as in [`Self::new`].
    ///
    /// # Errors
    /// - The initial Section Header Block cannot be decoded or fails strict validation.
    /// - The input cannot be read.
    pub fn with_capacity(reader: R, capacity: usize, strict: bool) -> Result<Self, PcapNgReadError> {
        let mut reader = ReadBuffer::with_capacity(reader, capacity);
        let parser = reader
            .parse_with(|src| PcapNgParser::new(src, strict))
            .map_err(|kind| PcapNgReadError::new(0, 0, kind))?;
        Ok(Self {
            parser,
            reader,
            poisoned: false,
            blocks_read: 1,
        })
    }

    /// Returns the next [`Block`] and the [`PcapNgState`].
    ///
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error and the reader remains poisoned.
    ///
    /// Use this when you need typed block data.
    ///
    /// The `strict` setting controls validation of blocks.
    /// State-changing blocks are checked before updating the state.
    /// Typed decoding checks representations and individual options even when `strict` is false.
    ///
    /// # Errors
    /// - Includes the block number and its starting byte offset.
    /// - On [`PcapNgReadErrorKind::Block`], the block is skipped.
    /// - State-changing block failures return [`PcapNgReadErrorKind::StateUpdate`] and poison the reader without changing state.
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error poisons the reader.
    ///   Later calls return [`None`].
    #[must_use = "the result contains either the next block or a read error"]
    pub fn next_block<'a>(&'a mut self) -> Option<Result<(Block<'a>, &'a PcapNgState), PcapNgReadError>> {
        if self.poisoned {
            return None;
        }

        let block_number = self.blocks_read;
        let offset = self.reader.bytes_used;

        let res = match self.reader.has_data_left() {
            Ok(true) => {
                let res: Result<RawBlock<'_>, PcapNgReadErrorKind> = self
                    .reader
                    .parse_with(|src| self.parser.parse_raw_block(src, self.parser.strict()))
                    .inspect(|_| self.blocks_read += 1);

                // # SAFETY
                // The raw block borrows only from the reader's internal buffer.
                // The returned lifetime is tied to `&'a mut self`, which prevents that buffer from being mutated.
                let res: Result<RawBlock<'a>, PcapNgReadErrorKind> = unsafe { std::mem::transmute(res) };
                res.and_then(|raw_block| {
                    let block = raw_block.try_into_block(&self.parser.state)?;

                    if self.parser.strict()
                        && !matches!(&block, Block::SectionHeader(_) | Block::InterfaceDescription(_))
                    {
                        block.validate(&self.parser.state)?;
                    }

                    Ok((block, &self.parser.state))
                })
            }
            Ok(false) => return None,
            Err(e) => Err(PcapNgReadErrorKind::Io(e)),
        }
        .map_err(|kind| PcapNgReadError::new(block_number, offset, kind))
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Returns the next [`RawBlock`] and the [`PcapNgState`].
    ///
    /// [`None`] means that the reader reached the end of input or a previous
    /// call returned a fatal error and the reader remains poisoned.
    ///
    /// Use this when you need raw block data or want to parse an unsupported
    /// block type.
    ///
    /// Use the returned state with [`RawBlock::try_into_block`] to decode a
    /// block, then with [`Block::validate`] to check it semantically.
    /// The `strict` setting does not affect this method.
    /// Checks framing and decodes state-changing blocks without semantic validation.
    /// Decoding still checks representations and individual options.
    /// Other block bodies remain undecoded.
    ///
    /// # Errors
    /// - Includes the block number and its starting byte offset.
    /// - Retry a non-fatal I/O error by calling this method again.
    /// - A fatal error poisons the reader.
    ///   Later calls return [`None`].
    #[must_use = "the result contains either the next raw block or a read error"]
    pub fn next_raw_block<'a>(&'a mut self) -> Option<Result<(RawBlock<'a>, &'a PcapNgState), PcapNgReadError>> {
        if self.poisoned {
            return None;
        }

        let block_number = self.blocks_read;
        let offset = self.reader.bytes_used;

        let res = match self.reader.has_data_left() {
            Ok(true) => {
                let res: Result<RawBlock<'_>, PcapNgReadErrorKind> = self
                    .reader
                    .parse_with(|src| self.parser.next_raw_block(src))
                    .inspect(|_| self.blocks_read += 1);

                // # SAFETY
                // The raw block borrows only from the reader's internal buffer.
                // The returned lifetime is tied to `&'a mut self`, which prevents that buffer from being mutated.
                let res: Result<RawBlock<'a>, PcapNgReadErrorKind> = unsafe { std::mem::transmute(res) };
                res.map(|blk| (blk, &self.parser.state))
            }
            Ok(false) => return None,
            Err(e) => Err(PcapNgReadErrorKind::Io(e)),
        }
        .map_err(|kind| PcapNgReadError::new(block_number, offset, kind))
        .inspect_err(|error| {
            self.poisoned |= error.is_fatal();
        });

        Some(res)
    }

    /// Returns whether a fatal error has poisoned the reader.
    /// While poisoned, subsequent reads return [`None`].
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    /// Allows reading again after a fatal error.
    /// This keeps the buffered bytes and section and interface state unchanged.
    ///
    /// # Safety
    /// The caller must ensure the unread bytes and underlying input can be read
    /// as blocks under the current section and interface state.
    /// Otherwise later reads may repeat the error or interpret data incorrectly.
    pub unsafe fn reset_poisoned(&mut self) {
        self.poisoned = false;
    }

    /// Returns whether the initial section header and typed blocks are semantically validated.
    pub fn strict(&self) -> bool {
        self.parser.strict()
    }

    /// Returns the current [`PcapNgState`].
    pub fn state(&self) -> &PcapNgState {
        self.parser.state()
    }

    /// Consumes the reader and returns an iterator over owned packets.
    ///
    /// Non-packet blocks are skipped.
    /// Non-fatal errors are yielded without
    /// stopping the iterator; polling it again continues reading.
    /// A fatal error is yielded once, then iteration ends.
    pub fn packets(self) -> PcapNgPacketIterator<R> {
        PcapNgPacketIterator { reader: self }
    }

    /// Consumes the capture reader and returns the wrapped reader.
    /// Unread buffered bytes are discarded.
    /// The wrapped reader may be positioned beyond [`Self::bytes_parsed`].
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Gets a reference to the wrapped reader.
    /// Its position may be ahead of [`Self::bytes_parsed`] because of buffered input.
    pub fn get_ref(&self) -> &R {
        self.reader.get_ref()
    }

    /// Returns the consumed byte count, including the initial header and skipped records.
    /// This can be smaller than the bytes read from the wrapped reader.
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
/// - On [`PcapNgReadErrorKind::Block`], the error is returned and the block is skipped.
/// - Retry a non-fatal I/O error by polling the iterator again.
/// - A fatal error is yielded once.
///   Later polls return [`None`].
///
/// # Example
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcap_file::pcapng::PcapNgReader;
///
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let file = File::open("tests/pcapng/little_endian/basic/test001.pcapng")?;
///     let reader = PcapNgReader::new(file, true)?;
///
///     // Iterator packets own their data and can be retained after the next poll.
///     for result in reader.packets() {
///         match result {
///             Ok(packet) => println!("{} bytes", packet.data.len()),
///             Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
///             Err(error) => return Err(error.into()),
///         }
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct PcapNgPacketIterator<R: Read> {
    /// Capture reader supplying owned iterator packets.
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
    /// Owned packet or positioned read error yielded by this iterator.
    type Item = Result<PcapNgPacket<'static>, PcapNgReadError>;
    /// Returns the next owned packet or read error.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let block_number = self.reader.blocks_read;
            let offset = self.reader.bytes_parsed();

            match self.reader.next_block() {
                Some(Ok((block, state))) => {
                    let type_ = block.type_code();
                    match PcapNgPacket::from_block(block, state) {
                        Ok(packet) => return Some(Ok(packet.into_owned())),
                        Err(PacketConversionError::NotPacket(_)) => continue,
                        Err(PacketConversionError::InvalidInterfaceId(id)) => {
                            let kind = BlockError {
                                type_,
                                source: Box::new(BlockValidationError::InvalidInterfaceId(id)),
                            }
                            .into();
                            return Some(Err(PcapNgReadError::new(block_number, offset, kind)));
                        }
                    }
                }
                Some(Err(error)) => return Some(Err(error)),
                None => return None,
            }
        }
    }
}
