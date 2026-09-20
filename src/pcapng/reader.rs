/* ----- Imports ----- */

use std::io::Read;

use super::blocks::block_common::{Block, RawBlock};
use super::{PcapNgPacket, PcapNgParser, PcapNgState};
use crate::pcapng::errors::{BlockConversionError, ContentValidationError, PacketConversionError, PcapNgReadError};
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
}

impl<R: Read> PcapNgReader<R> {
    /// Creates a new [`PcapNgReader`] from a reader.
    ///
    /// Parses the first block, which must be a Section Header Block.
    /// When `strict` is true, typed blocks are semantically validated.
    /// Raw operations leave semantic validation to the caller.
    pub fn new(reader: R, strict: bool) -> Result<Self, PcapNgReadError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(|src| PcapNgParser::new(src, strict))?;
        Ok(Self { parser, reader })
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
        Ok(Self { parser, reader })
    }

    /// Returns the next typed block and state, validating the block in strict mode.
    /// [`None`] means that the reader has reached the EoF.
    /// Won't advance the reader past any malformed packets.
    ///
    /// # Errors
    /// - Only some variants of [`PcapNgReadError::Io`] are directly recoverable.
    /// - [`PcapNgReadError::BlockConversion`] for non-state blocks can be recovered by calling [`Self::next_raw_block`].
    ///   Malformed Section Header or Interface Description blocks may still fail there because the reader must decode them to keep its state consistent.
    /// - Other errors will prevent the reader from advancing further.
    #[must_use = "Not checking the result can lead to an infinite loop because the reader may not advance on error"]
    pub fn next_block<'a>(&'a mut self) -> Option<Result<(Block<'a>, &'a PcapNgState), PcapNgReadError>> {
        match self.reader.has_data_left() {
            Ok(true) => {
                // # SAFETY
                // Block must NOT contain a mutable reference to the state.
                // Keep the annotations to be sure that only the lifetime is transmuted.
                let res: Result<Block<'_>, PcapNgReadError> = self.reader.parse_with(|src| self.parser.next_block(src));
                let res: Result<Block<'_>, PcapNgReadError> = unsafe { std::mem::transmute(res) };

                let state = &self.parser.state;

                Some(res.map(|blk| (blk, state)))
            }
            Ok(false) => None,
            Err(e) => Some(Err(PcapNgReadError::Io(e))),
        }
    }

    /// Returns the next [`RawBlock`] and the current [`PcapNgState`].
    /// [`None`] means that the reader has reached the EoF.
    /// More permissive than [`Self::next_block`].
    ///
    /// Strict mode does not validate raw block contents. Decode with
    /// [`RawBlock::try_into_block`] and call [`Block::validate`] explicitly.
    /// Section Header and Interface Description blocks are still decoded to
    /// maintain state, without semantic validation.
    ///
    /// # Errors
    /// - Only some variants of [`PcapNgReadError::Io`] are directly recoverable.
    /// - [`PcapNgReadError::StateUpdate`] can happen when a state-changing raw block cannot be decoded.
    /// - All other errors will prevent the reader from advancing further.
    #[must_use = "Not checking the result can lead to an infinite loop because the reader may not advance on error"]
    pub fn next_raw_block<'a>(&'a mut self) -> Option<Result<(RawBlock<'a>, &'a PcapNgState), PcapNgReadError>> {
        match self.reader.has_data_left() {
            Ok(true) => {
                // # SAFETY
                // Block must NOT contain a mutable reference to the state.
                // Keep the annotations to be sure that only the lifetime is transmuted.
                let res: Result<RawBlock<'_>, PcapNgReadError> =
                    self.reader.parse_with(|src| self.parser.next_raw_block(src));
                let res: Result<RawBlock<'_>, PcapNgReadError> = unsafe { std::mem::transmute(res) };

                let state = &self.parser.state;

                Some(res.map(|blk| (blk, state)))
            }
            Ok(false) => None,
            Err(e) => Some(Err(PcapNgReadError::Io(e))),
        }
    }

    /// Returns whether this reader and its packet iterator validate typed blocks.
    pub fn strict(&self) -> bool {
        self.parser.strict()
    }

    /// Returns the current parsing state.
    pub fn state(&self) -> &PcapNgState {
        self.parser.state()
    }

    /// Consumes the reader and returns an iterator over its packets.
    pub fn packets(self) -> PcapNgPacketIterator<R> {
        PcapNgPacketIterator {
            reader: self,
            err: false,
        }
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
/// Uses the reader's strict setting and stops after the first error.
/// Packet data is copied out of the internal read buffer.
/// Packets contain datalink, timestamp, original length, and data.
/// The datalink is resolved from the packet's interface in the current section.
///
/// Use [`PcapNgReader::next_block`] for typed blocks and their state, or
/// [`PcapNgReader::next_raw_block`] for unsupported or malformed content.
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
    err: bool,
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
        if self.err {
            return None;
        }

        loop {
            match self.reader.next_block() {
                Some(Ok((block, state))) => {
                    let type_ = block.type_code();
                    match PcapNgPacket::from_block(block, state) {
                        Ok(packet) => return Some(Ok(packet.into_owned())),
                        Err(PacketConversionError::NotPacket(_)) => continue,
                        Err(PacketConversionError::InvalidInterfaceId(id)) => {
                            self.err = true;
                            return Some(Err(BlockConversionError {
                                type_,
                                source: Box::new(ContentValidationError::InvalidInterfaceId(id).into()),
                            }
                            .into()));
                        }
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
