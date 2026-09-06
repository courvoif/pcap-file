use std::borrow::Cow;
use std::io::Read;
use std::time::Duration;

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::{PcapNgParser, PcapNgState};
use crate::pcapng::blocks::packet::PacketBlock;
use crate::pcapng::blocks::simple_packet::SimplePacketBlock;
use crate::pcapng::errors::PcapNgReadError;
use crate::read_buffer::ReadBuffer;

/// Reads a pcapng stream from a reader.
///
/// Buffers data from the underlying reader internally.
///
/// # Example
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
    /// Parses the first block, which must be a valid [`SectionHeaderBlock`].
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
    /// Parses the first block, which must be a valid [`SectionHeaderBlock`].
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
    #[must_use = "the result must be handled before reading another block"]
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
    #[must_use = "the result must be handled before reading another block"]
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

    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        self.parser.section()
    }

    /// Returns the current [`InterfaceDescriptionBlock`] values.
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        self.parser.interfaces()
    }

    /// Returns the [`InterfaceDescriptionBlock`] corresponding to the given packet.
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock<'_>> {
        self.interfaces().get(packet.interface_id as usize)
    }

    /// Consumes the [`PcapNgReader`], returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Returns a reference to the wrapped reader.
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
/// # Example
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
    /// Returns a reference to the wrapped [`PcapNgReader`].
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
                Some(Ok((Block::EnhancedPacket(packet), _))) => {
                    return Some(Ok(PcapNgPacket::Enhanced(packet.into_owned())));
                }
                Some(Ok((Block::SimplePacket(packet), _))) => {
                    return Some(Ok(PcapNgPacket::Simple(packet.into_owned())));
                }
                Some(Ok((Block::Packet(packet), _))) => {
                    return Some(Ok(PcapNgPacket::Deprecated(packet.into_owned())));
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    self.err = true;
                    return Some(Err(error));
                }
                None => return None,
            }
        }
    }
}

/* ----- PcapNgPacket ----- */

/// A packet read from any pcapng packet block type.
pub enum PcapNgPacket<'a> {
    /// A packet from an Enhanced Packet Block.
    Enhanced(EnhancedPacketBlock<'a>),
    /// A packet from a Simple Packet Block.
    Simple(SimplePacketBlock<'a>),
    /// A packet from the obsolete Packet Block format.
    Deprecated(PacketBlock<'a>),
}

impl<'a> PcapNgPacket<'a> {
    /// Returns the packet data as a slice.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Enhanced(packet) => &packet.data,
            Self::Simple(packet) => &packet.data,
            Self::Deprecated(packet) => &packet.data,
        }
    }

    /// Returns the packet data, preserving whether it is borrowed or owned.
    pub fn into_data(self) -> Cow<'a, [u8]> {
        match self {
            Self::Enhanced(packet) => packet.data,
            Self::Simple(packet) => packet.data,
            Self::Deprecated(packet) => packet.data,
        }
    }

    /// Returns the packet timestamp, or [`None`] for a Simple Packet Block.
    pub fn timestamp(&self) -> Option<Duration> {
        match self {
            Self::Enhanced(packet) => Some(packet.timestamp),
            Self::Simple(_) => None,
            Self::Deprecated(packet) => Some(packet.timestamp),
        }
    }

    /// Returns the packet's original length on the wire.
    pub fn original_len(&self) -> u32 {
        match self {
            Self::Enhanced(packet) => packet.original_len,
            Self::Simple(packet) => packet.original_len,
            Self::Deprecated(packet) => packet.original_len,
        }
    }
}

impl<'a> From<EnhancedPacketBlock<'a>> for PcapNgPacket<'a> {
    fn from(value: EnhancedPacketBlock<'a>) -> Self {
        Self::Enhanced(value)
    }
}

impl<'a> From<SimplePacketBlock<'a>> for PcapNgPacket<'a> {
    fn from(value: SimplePacketBlock<'a>) -> Self {
        Self::Simple(value)
    }
}

impl<'a> From<PacketBlock<'a>> for PcapNgPacket<'a> {
    fn from(value: PacketBlock<'a>) -> Self {
        Self::Deprecated(value)
    }
}

/* ----- Tests ----- */

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::Duration;

    use super::PcapNgPacket;
    use crate::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use crate::pcapng::blocks::packet::PacketBlock;
    use crate::pcapng::blocks::simple_packet::SimplePacketBlock;

    #[test]
    fn packet_accessors_cover_all_packet_block_types() {
        let enhanced = PcapNgPacket::from(EnhancedPacketBlock {
            timestamp: Duration::from_secs(1),
            original_len: 4,
            data: Cow::Borrowed(&[1, 2]),
            ..Default::default()
        });
        assert_eq!(enhanced.data(), [1, 2]);
        assert_eq!(enhanced.timestamp(), Some(Duration::from_secs(1)));
        assert_eq!(enhanced.original_len(), 4);

        let simple = PcapNgPacket::from(SimplePacketBlock {
            original_len: 5,
            data: Cow::Borrowed(&[3, 4]),
        });
        assert_eq!(simple.data(), [3, 4]);
        assert_eq!(simple.timestamp(), None);
        assert_eq!(simple.original_len(), 5);

        let deprecated = PcapNgPacket::from(PacketBlock {
            interface_id: 0,
            drop_count: 0,
            timestamp: Duration::from_secs(2),
            original_len: 6,
            data: Cow::Borrowed(&[5, 6]),
            options: Vec::new(),
        });
        assert_eq!(deprecated.data(), [5, 6]);
        assert_eq!(deprecated.timestamp(), Some(Duration::from_secs(2)));
        assert_eq!(deprecated.original_len(), 6);
    }

    #[test]
    fn into_data_preserves_ownership() {
        let packet = PcapNgPacket::from(SimplePacketBlock {
            original_len: 2,
            data: Cow::Owned(vec![1, 2]),
        });

        assert!(matches!(packet.into_data(), Cow::Owned(data) if data == [1, 2]));
    }
}
