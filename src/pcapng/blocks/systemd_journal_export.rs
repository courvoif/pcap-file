use crate::errors::PcapError;
use crate::DataLink;
use std::io::Read;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::peek_reader::PeekReader;
use std::borrow::Cow;


/// The systemd Journal Export Block is a lightweight containter for systemd Journal Export Format entry data.
#[derive(Clone, Debug)]
pub struct SystemdJournalExportBlock<'a> {

    /// A journal entry as described in the Journal Export Format documentation.
    pub journal_entry: &'a [u8],
}

impl<'a> SystemdJournalExportBlock<'a> {

    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(Self, &'a[u8]), PcapError> {

        let packet = SystemdJournalExportBlock {
            journal_entry: slice,
        };

        Ok((packet, &[]))
    }
}
