use std::borrow::Cow;
use std::io::{Result as IoResult, Write};

use byteorder::ByteOrder;
use derive_into_owned::IntoOwned;

use crate::errors::PcapError;
use crate::pcapng::{PcapNgBlock, BlockType, Block};

/// The systemd Journal Export Block is a lightweight containter for systemd Journal Export Format entry data.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SystemdJournalExportBlock<'a> {

    /// A journal entry as described in the Journal Export Format documentation.
    pub journal_entry: Cow<'a, [u8]>,
}

impl<'a> PcapNgBlock<'a> for SystemdJournalExportBlock<'a> {

    const BLOCK_TYPE: BlockType = BlockType::SystemdJournalExport;

    fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {

        let packet = SystemdJournalExportBlock {
            journal_entry: Cow::Borrowed(slice),
        };

        Ok((&[], packet))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {

        writer.write_all(&self.journal_entry)?;

        let pad_len = (4 - (self.journal_entry.len() as usize % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(self.journal_entry.len() + pad_len)
    }

    fn into_parsed(self) -> Block<'a> {
        Block::SystemdJournalExport(self)
    }
}
