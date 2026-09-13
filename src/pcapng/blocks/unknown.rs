//! Unknown Block.

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::ByteOrder;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use crate::pcapng::{
    PcapNgState,
    errors::{BlockContentParseError, ContentValidationError, PcapNgWriteError},
};

/// Unknown Block.
///
/// Stores a pcapng block whose type is not recognized.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownBlock<'a> {
    /// Numeric block type.
    pub type_: u32,
    /// Total block length.
    pub length: u32,
    /// Unparsed block body.
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownBlock<'a> {
    /// Creates a new [`UnknownBlock`].
    ///
    /// `length` is the total block length, including the 12 bytes occupied by
    /// the block type, the two length fields, and any padding in `value`.
    pub fn new(type_: u32, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock {
            type_,
            length,
            value: Cow::Borrowed(value),
        }
    }
}

impl<'a> PcapNgBlock<'a> for UnknownBlock<'a> {
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        _slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockContentParseError>
    where
        Self: Sized,
    {
        Err(BlockContentParseError::UnknownBlock)
    }

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError> {
        let expected = self.value.len() + 12;

        if self.length as usize != expected {
            return Err(PcapNgWriteError::validation_error(
                "UnknownBlock.length",
                ContentValidationError::UnknownBlockLengthMismatch {
                    expected,
                    actual: self.length,
                },
            ));
        }

        writer.write_all(&self.value)?;
        Ok(self.value.len())
    }

    fn into_block(self) -> Block<'a> {
        Block::Unknown(self)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use byteorder_slice::BigEndian;

    use super::*;
    use crate::pcapng::errors::{ContentValidationError, PcapNgWriteError};

    #[test]
    fn typed_parse_returns_an_error() {
        let error = UnknownBlock::from_slice::<BigEndian>(&PcapNgState::default(), &[]).unwrap_err();
        assert!(matches!(error, BlockContentParseError::UnknownBlock));
    }

    #[test]
    fn write_rejects_a_length_that_does_not_match_the_value() {
        let block = UnknownBlock {
            type_: 42,
            length: 16,
            value: Cow::Borrowed(&[1, 2, 3, 4, 5, 6, 7, 8]),
        };

        let error = block
            .write_to::<BigEndian, _>(&PcapNgState::default(), &mut Vec::new())
            .unwrap_err();
        assert!(matches!(
            error,
            PcapNgWriteError::Validation { source, .. }
                if matches!(
                    *source,
                    ContentValidationError::UnknownBlockLengthMismatch {
                        expected: 20,
                        actual: 16
                    }
                )
        ));
    }
}
