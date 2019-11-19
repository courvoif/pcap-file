use crate::errors::PcapError;
use byteorder::ByteOrder;
use std::borrow::Cow;
use derive_into_owned::IntoOwned;


/// The systemd Journal Export Block is a lightweight containter for systemd Journal Export Format entry data.
#[derive(Clone, Debug, IntoOwned)]
pub struct SystemdJournalExportBlock<'a> {

    /// A journal entry as described in the Journal Export Format documentation.
    pub journal_entry: Cow<'a, [u8]>,
}

impl<'a> SystemdJournalExportBlock<'a> {

    pub fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&'a[u8], Self), PcapError> {

        let packet = SystemdJournalExportBlock {
            journal_entry: Cow::Borrowed(slice),
        };

        Ok((&[], packet))
    }
}
