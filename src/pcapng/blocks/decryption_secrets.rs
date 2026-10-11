//! [`Decryption Secrets Block`](DecryptionSecretsBlock).

/* ----- Imports ----- */

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock, checked_body_len};
use super::opt_common::{CommonOption, PcapNgOption, opts_from_slice, validate_opts, write_opts_to};
use crate::pcapng::PcapNgState;
use crate::pcapng::errors::{BlockValidationError, OptionEntryError, WriteError};

/* ----- Secrets type codes ----- */

/// SSH key-log data (`SSHK`).
pub const SSH_KEY_LOG: u32 = 0x5353484B;
/// TLS key-log data (`TLSK`).
pub const TLS_KEY_LOG: u32 = 0x544C534B;
/// OPC UA key-log data (`UAKL`).
pub const OPC_UA_KEY_LOG: u32 = 0x55414B4C;
/// WireGuard key-log data (`WGKL`).
pub const WIREGUARD_KEY_LOG: u32 = 0x57474B4C;
/// ZigBee network key followed by its little-endian PAN ID (`ZNWK`).
pub const ZIGBEE_NWK_KEY: u32 = 0x5A4E574B;
/// ZigBee application link key followed by little-endian PAN and node IDs (`ZAPS`).
pub const ZIGBEE_APS_KEY: u32 = 0x5A415053;
/// ESP security association data in CSV format (`ESPS`).
pub const ESP_SECRETS: u32 = 0x45535053;

/* ----- DecryptionSecretsBlock ----- */

/// Stores secret data used to decrypt packets in a capture.
/// Write it before packets that depend on those secrets.
/// Multiple blocks are allowed, and no interface is required.
/// See the [pcapng specification](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html#section-4.7) for payload formats.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct DecryptionSecretsBlock<'a> {
    /// Format identifier, such as [`TLS_KEY_LOG`] or [`ZIGBEE_NWK_KEY`].
    /// Unknown type codes are preserved.
    pub secrets_type: u32,
    /// Secret bytes, excluding alignment padding.
    /// Supply data encoded for [`Self::secrets_type`]; payload contents are not validated.
    /// Payload byte order is defined by its format, independently of the section.
    pub secrets_data: Cow<'a, [u8]>,
    /// Options accompanying the secret data.
    pub options: Vec<DecryptionSecretsOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for DecryptionSecretsBlock<'a> {
    /// Numeric type code of this block.
    const TYPE: u32 = 0x0000000A;
    /// Human-readable name of this block.
    const NAME: &'static str = "Decryption Secrets Block";

    /// Decodes the header, unpadded secret bytes, and options using the supplied section state.
    fn from_body<B: ByteOrder>(
        state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError> {
        if slice.len() < 8 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 8,
                actual: slice.len(),
            });
        }

        let secrets_type = slice.read_u32::<B>().expect("header length checked above");
        let secrets_len = slice.read_u32::<B>().expect("header length checked above") as usize;
        let pad_len = (4 - secrets_len % 4) % 4;
        let padded_len = checked_body_len(secrets_len, pad_len)?;

        if slice.len() < padded_len {
            return Err(BlockValidationError::ContentTooSmall {
                needed: padded_len,
                actual: slice.len(),
            });
        }

        let secrets_data = Cow::Borrowed(&slice[..secrets_len]);
        let (rem, options) = opts_from_slice::<B, DecryptionSecretsOption>(state, None, &slice[padded_len..])?;

        Ok((
            rem,
            Self {
                secrets_type,
                secrets_data,
                options,
            },
        ))
    }

    /// Writes the header, secret bytes, zero padding, and options using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        let secrets_len = u32::try_from(self.secrets_data.len()).map_err(|_| {
            WriteError::Other(BlockValidationError::BlockTooLarge {
                actual: self.secrets_data.len() as u64,
                maximum: u32::MAX as u64,
            })
        })?;
        let pad_len = (4 - self.secrets_data.len() % 4) % 4;
        let body_len = checked_body_len(self.secrets_data.len(), 8 + pad_len).map_err(WriteError::Other)?;

        writer.write_u32::<B>(self.secrets_type)?;
        writer.write_u32::<B>(secrets_len)?;
        writer.write_all(&self.secrets_data)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len = write_opts_to::<B, _, _>(&self.options, state, None, writer)
            .map_err(|error| error.map_other(BlockValidationError::Option))?;

        checked_body_len(body_len, opt_len).map_err(WriteError::Other)
    }

    /// Checks the secret length and common options without interpreting payload contents.
    fn validate(&self, state: &PcapNgState) -> Result<(), BlockValidationError> {
        u32::try_from(self.secrets_data.len()).map_err(|_| BlockValidationError::BlockTooLarge {
            actual: self.secrets_data.len() as u64,
            maximum: u32::MAX as u64,
        })?;

        validate_opts(&self.options, state, None).map_err(BlockValidationError::Option)
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        Block::DecryptionSecrets(self)
    }
}

/* ----- DecryptionSecretsOption ----- */

/// Decryption Secrets Block options.
/// There are no block-specific options.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum DecryptionSecretsOption<'a> {
    /// A common option applicable to any block type.
    Common(CommonOption<'a>),
}

impl<'a> PcapNgOption<'a> for DecryptionSecretsOption<'a> {
    /// Decodes an option value for the supplied option code.
    fn from_content<B: ByteOrder>(
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        code: u16,
        slice: &'a [u8],
    ) -> Result<Self, OptionEntryError> {
        Ok(Self::Common(CommonOption::from_content::<B>(code, slice)?))
    }

    /// Writes this value using the selected byte order.
    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        _interface_id: Option<u32>,
        writer: &mut W,
    ) -> Result<usize, WriteError<OptionEntryError>> {
        match self {
            Self::Common(option) => option.write_to::<B, W>(writer),
        }
    }

    /// Accepts common options without additional block-specific constraints.
    fn validate(&self, _state: &PcapNgState, _interface_id: Option<u32>) -> Result<(), OptionEntryError> {
        Ok(())
    }

    /// Returns the encoded option code.
    fn code(&self) -> u16 {
        match self {
            Self::Common(option) => option.code(),
        }
    }

    /// Returns the option name for its code.
    fn name(code: u16) -> &'static str {
        CommonOption::code_name(code)
    }
}
