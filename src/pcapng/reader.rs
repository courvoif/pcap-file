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
    /// Creates a new [`PcapNgReader`] from a reader.
    ///
    /// Parses the first block, which must be a Section Header Block.
    /// When `strict` is true, every typed block is semantically validated.
    /// Section Header and Interface Description blocks are always validated
    /// because the reader needs them to maintain its state.
    /// Raw operations leave validation of all other block types to the caller.
    pub fn new(reader: R, strict: bool) -> Result<Self, PcapNgReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(|src| PcapNgParser::new(src, strict))?;
        Ok(Self {
            parser,
            reader,
            poisoned: false,
        })
    }

    /// Creates a new [`PcapNgReader`] with a custom internal buffer capacity.
    ///
    /// Use this when the stream can contain blocks larger than the default
    /// reader buffer.
    ///
    /// Parses the initial Section Header Block. `strict` controls semantic
    /// validation of typed blocks, as in [`Self::new`].
    pub fn with_capacity(reader: R, capacity: usize, strict: bool) -> Result<Self, PcapNgReadError> {
        let mut reader = ReadBuffer::with_capacity(reader, capacity);
        let parser = reader.parse_with(|src| PcapNgParser::new(src, strict))?;
        Ok(Self {
            parser,
            reader,
            poisoned: false,
        })
    }

    /// Returns the next typed block and the state after applying that block.
    ///
    /// A well-framed non-state block is consumed before typed conversion and
    /// semantic validation. If either step returns
    /// [`PcapNgReadError::Block`], the block has already been skipped
    /// and the next call continues with the following block.
    ///
    /// [`None`] means that the reader has reached the end of input or was
    /// previously poisoned by a fatal error.
    ///
    /// # Errors
    /// - [`PcapNgReadError::Block`] is non-fatal and consumes the
    ///   rejected block.
    /// - I/O errors with [`std::io::ErrorKind::Interrupted`],
    ///   [`std::io::ErrorKind::WouldBlock`], or
    ///   [`std::io::ErrorKind::TimedOut`] are non-fatal. Calling this method
    ///   again retries without losing buffered input.
    /// - Invalid framing, state update errors, and all other I/O errors are
    ///   fatal. The reader returns the error once and then becomes poisoned.
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

    /// Returns the next [`RawBlock`] and the current [`PcapNgState`].
    /// More permissive than [`Self::next_block`].
    ///
    /// Strict mode does not validate non-state raw block contents. Decode with
    /// [`RawBlock::try_into_block`] and call [`Block::validate`] explicitly when
    /// semantic validation is wanted.
    ///
    /// Section Header and Interface Description blocks are always decoded and
    /// validated before the reader updates its state.
    ///
    /// [`None`] means that the reader has reached the end of input or was
    /// previously poisoned by a fatal error.
    ///
    /// # Errors
    /// - I/O errors with [`std::io::ErrorKind::Interrupted`],
    ///   [`std::io::ErrorKind::WouldBlock`], or
    ///   [`std::io::ErrorKind::TimedOut`] are non-fatal. Calling this method
    ///   again retries without losing buffered input.
    /// - Invalid framing, state update errors, and all other I/O errors are
    ///   fatal. The reader returns the error once and then becomes poisoned.
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

    /// Returns whether this reader and its packet iterator validate non-state typed blocks.
    ///
    /// State-changing blocks are always validated.
    pub fn strict(&self) -> bool {
        self.parser.strict()
    }

    /// Returns the current parsing state.
    pub fn state(&self) -> &PcapNgState {
        self.parser.state()
    }

    /// Consumes the reader and returns an iterator over owned packets.
    ///
    /// Non-packet blocks are skipped. Non-fatal errors are yielded without
    /// stopping the iterator; polling it again continues reading. A fatal error
    /// is yielded once, after which the poisoned reader returns [`None`].
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

/// Iterator over owned packets, skipping non-packet blocks.
///
/// Uses the reader's strict setting for non-state blocks. State-changing blocks
/// are always validated. Non-fatal errors are yielded and iteration can continue
/// when polled again. A fatal error is yielded once, then the poisoned reader
/// ends the iterator.
///
/// Packet data is copied out of the internal read buffer.
/// Packets contain datalink, timestamp, original length, and data.
/// The datalink is resolved from the packet's interface in the current section.
///
/// Use [`PcapNgReader::next_block`] for typed blocks and their state.
/// Use [`PcapNgReader::next_raw_block`] from the start when unsupported or
/// malformed non-state content must be preserved.
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
