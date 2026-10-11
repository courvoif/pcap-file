//! [`Systemd Journal Export Block`](SystemdJournalExportBlock).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::ByteOrder;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock, checked_body_len};
use crate::pcapng::{
    PcapNgState,
    errors::{BlockValidationError, WriteError},
};

/* ----- Journal entries ----- */

/// The Systemd Journal Export Block is a lightweight container for systemd Journal Export Format entry data.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SystemdJournalExportBlock<'a> {
    /// Journal Export Format bytes, including trailing block padding when decoded.
    /// The library does not validate the journal entry format.
    pub journal_entry: Cow<'a, [u8]>,
}

impl<'a> PcapNgBlock<'a> for SystemdJournalExportBlock<'a> {
    /// Numeric type code of this block.
    const TYPE: u32 = 0x00000009;
    /// Human-readable name of this block.
    const NAME: &'static str = "systemd Journal Export Block";

    /// Decodes this block body using the supplied section state.
    fn from_body<B: ByteOrder>(
        _state: &PcapNgState,
        slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError> {
        let packet = SystemdJournalExportBlock {
            journal_entry: Cow::Borrowed(slice),
        };
        Ok((&[], packet))
    }

    /// Writes this block body using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        let pad_len = (4 - (self.journal_entry.len() % 4)) % 4;
        let body_len = checked_body_len(self.journal_entry.len(), pad_len).map_err(WriteError::Other)?;

        writer.write_all(&self.journal_entry)?;

        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(body_len)
    }

    /// Checks the constraints applicable to this value.
    fn validate(&self, _state: &PcapNgState) -> Result<(), BlockValidationError> {
        Ok(())
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::SystemdJournalExport(self)
    }
}
