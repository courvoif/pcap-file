//! Custom blocks, options, and payload codecs.
//!
//! Use copiable payloads when bytes remain valid after being copied between sections.
//! Use non-copiable payloads when section or interface state is required.
//! Decoded custom block payloads include alignment padding; option values do not.

/* ----- Imports ----- */

use std::borrow::Cow;
use std::error::Error;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::{ReadBytesExt, WriteBytesExt};
use thiserror::Error;

use super::block_common::{Block, PcapNgBlock, checked_body_len};
use crate::pcapng::PcapNgState;
use crate::pcapng::blocks::opt_common::CommonOption;
use crate::pcapng::errors::OptionEntryError;
use crate::pcapng::errors::{BlockValidationError, WriteError};

/* ----- traits for Custom Payload ----- */

/// Common interface for copiable custom block and custom option payloads.
pub trait CustomPayloadCopiable<'a> {
    /// Private Enterprise Number of the entity which defined this payload format.
    const PEN: u32;

    /// Error returned by [`CustomPayloadCopiable::from_slice()`].
    type FromSliceError: Error + Sync + Send + 'static;

    /// Error returned by [`CustomPayloadCopiable::write_to()`].
    type WriteToError: Error + Sync + Send + 'static;

    /// Decodes a recognized payload, returning `None` for an unrecognized payload format.
    /// Custom block slices can include trailing alignment padding.
    ///
    /// # Errors
    /// Return an error when a recognized format contains invalid or incomplete data.
    fn from_slice(slice: &'a [u8]) -> Result<Option<Self>, Self::FromSliceError>
    where
        Self: Sized;

    /// Write this payload into a writer.
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Self::WriteToError>;

    /// Serialize this payload into bytes.
    ///
    /// # Important
    /// Do not override.
    fn to_bytes(&self) -> Result<Vec<u8>, CustomError>
    where
        Self: Sized,
    {
        let mut data = Vec::new();
        self.write_to(&mut data).map_err(|e| CustomError {
            pen: Self::PEN,
            src: e.into(),
        })?;
        Ok(data)
    }
}

/// Common interface for non-copiable custom block and custom option payloads.
pub trait CustomPayloadNonCopiable<'a> {
    /// Private Enterprise Number of the entity which defined this payload format.
    const PEN: u32;

    /// State that may be required to parse/write the payload.
    type State;

    /// Error returned by [`CustomPayloadNonCopiable::from_slice()`].
    type FromSliceError: Error + Sync + Send + 'static;

    /// Error returned by [`CustomPayloadNonCopiable::write_to()`].
    type WriteToError: Error + Sync + Send + 'static;

    /// Decodes a recognized payload, returning `None` for an unrecognized payload format.
    /// Custom block slices can include trailing alignment padding.
    ///
    /// # Errors
    /// Return an error when a recognized format contains invalid or incomplete data.
    fn from_slice(state: &Self::State, slice: &'a [u8]) -> Result<Option<Self>, Self::FromSliceError>
    where
        Self: Sized;

    /// Write this payload into a writer.
    fn write_to<W: Write>(&self, state: &Self::State, writer: &mut W) -> Result<(), Self::WriteToError>;

    /// Serialize this payload into bytes.
    ///
    /// # Important
    /// Do not override.
    fn to_bytes(&self, state: &Self::State) -> Result<Vec<u8>, CustomError>
    where
        Self: Sized,
    {
        let mut data = Vec::new();
        self.write_to(state, &mut data).map_err(|e| CustomError {
            pen: Self::PEN,
            src: e.into(),
        })?;
        Ok(data)
    }
}

/// Common interface for custom block payloads.
///
/// # Important
/// Implement [`CustomPayloadCopiable`] or [`CustomPayloadNonCopiable`] to choose the encoding API.
pub trait CustomBlockPayload<'a> {
    /// Convert this payload into a copiable [`CustomBlock`].
    ///
    /// # Important
    /// Do not override.
    fn into_custom_block_copiable(self) -> Result<CustomBlock<'a, true>, CustomError>
    where
        Self: Sized,
        Self: CustomPayloadCopiable<'a>,
    {
        let data = self.to_bytes()?;
        Ok(CustomBlock {
            pen: Self::PEN,
            payload: Cow::Owned(data),
        })
    }

    /// Convert this payload into a non-copiable [`CustomBlock`].
    ///
    /// # Important
    /// Do not override.
    fn into_custom_block_non_copiable(self, state: &Self::State) -> Result<CustomBlock<'a, false>, CustomError>
    where
        Self: Sized,
        Self: CustomPayloadNonCopiable<'a>,
    {
        let data = self.to_bytes(state)?;
        Ok(CustomBlock {
            pen: Self::PEN,
            payload: Cow::Owned(data),
        })
    }
}

/// Common interface for custom option payloads.
///
/// # Important
/// Implement [`CustomPayloadCopiable`] or [`CustomPayloadNonCopiable`] to choose the encoding API.
pub trait CustomOptionPayload<'a> {
    /// Convert this payload into a copiable [`CustomBinaryOption`].
    ///
    /// # Important
    /// Do not override.
    fn into_custom_binary_option_copiable(self) -> Result<CustomBinaryOption<'a, true>, CustomError>
    where
        Self: Sized,
        Self: CustomPayloadCopiable<'a>,
    {
        let data = self.to_bytes()?;
        Ok(CustomBinaryOption {
            pen: Self::PEN,
            value: Cow::Owned(data),
        })
    }

    /// Convert this payload into a non-copiable [`CustomBinaryOption`].
    ///
    /// # Important
    /// Do not override.
    fn into_custom_binary_option_non_copiable(
        self,
        state: &Self::State,
    ) -> Result<CustomBinaryOption<'a, false>, CustomError>
    where
        Self: Sized,
        Self: CustomPayloadNonCopiable<'a>,
    {
        let data = self.to_bytes(state)?;
        Ok(CustomBinaryOption {
            pen: Self::PEN,
            value: Cow::Owned(data),
        })
    }
}

/* ----- Custom Error ----- */

/// Payload codec error associated with a private enterprise number.
#[derive(Debug, Error)]
#[error("Error in custom conversion for PEN {pen:#X}")]
pub struct CustomError {
    /// Pen of the custom block/option
    pub pen: u32,
    /// Source of the error
    #[source]
    pub src: Box<dyn Error + Sync + Send + 'static>,
}

/* ----- struct CustomBlock ----- */

/// Opaque custom block identified by a private enterprise number.
/// `COPIABLE` selects whether its bytes can be copied unchanged between sections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomBlock<'a, const COPIABLE: bool> {
    /// Private Enterprise Number of the entity which defined this block.
    pub pen: u32,
    /// Payload bytes, including any block alignment padding when decoded.
    /// Use an aligned fixed-size format or store a payload length to distinguish padding.
    pub payload: Cow<'a, [u8]>,
}

impl<'a, const COPIABLE: bool> CustomBlock<'a, COPIABLE> {
    // The into_owned method must be implemented manually,
    // since derive_into_owned can't handle the const generic.

    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomBlock<'static, COPIABLE> {
        CustomBlock {
            pen: self.pen,
            payload: Cow::Owned(self.payload.into_owned()),
        }
    }
}

impl<'a> CustomBlock<'a, true> {
    /// Converts this block's payload into a copiable custom payload type.
    /// Returns `None` if the PEN differs or the decoder does not recognize the format.
    ///
    /// # Errors
    /// Inspect the source error for a recognized payload that cannot be decoded.
    pub fn interpret<T>(&'a self) -> Result<Option<T>, CustomError>
    where
        T: CustomPayloadCopiable<'a> + CustomBlockPayload<'a>,
    {
        if self.pen != T::PEN {
            return Ok(None);
        }

        T::from_slice(&self.payload).map_err(|e| CustomError {
            pen: T::PEN,
            src: e.into(),
        })
    }
}

impl<'a> CustomBlock<'a, false> {
    /// Converts this block's payload into a non-copiable custom payload type.
    /// Returns `None` if the PEN differs or the decoder does not recognize the format.
    ///
    /// # Errors
    /// Inspect the source error for a recognized payload that cannot be decoded.
    pub fn interpret<T>(&'a self, state: &T::State) -> Result<Option<T>, CustomError>
    where
        T: CustomPayloadNonCopiable<'a> + CustomBlockPayload<'a>,
    {
        if self.pen != T::PEN {
            return Ok(None);
        }

        T::from_slice(state, &self.payload).map_err(|e| CustomError {
            pen: T::PEN,
            src: e.into(),
        })
    }
}

impl<'a, const COPIABLE: bool> PcapNgBlock<'a> for CustomBlock<'a, COPIABLE> {
    /// Numeric type code of this block.
    const TYPE: u32 = if COPIABLE { 0x00000BAD } else { 0x40000BAD };
    /// Human-readable name of this block.
    const NAME: &'static str = if COPIABLE {
        "Custom Block (Copiable)"
    } else {
        "Custom Block (Non-Copiable)"
    };
    /// Checks the constraints applicable to this value.
    fn validate(&self, _state: &PcapNgState) -> Result<(), BlockValidationError> {
        Ok(())
    }

    /// Decodes this block body using the supplied section state.
    fn from_body<B: ByteOrder>(
        _state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockValidationError>
    where
        Self: Sized,
    {
        if slice.len() < 4 {
            return Err(BlockValidationError::ContentTooSmall {
                needed: 4,
                actual: slice.len(),
            });
        }

        let pen = slice.read_u32::<B>().unwrap();
        Ok((
            &[],
            CustomBlock {
                pen,
                payload: Cow::Borrowed(slice),
            },
        ))
    }

    /// Writes this block body using the supplied section state.
    /// See [`PcapNgBlock::write_body_to`] for byte order and error handling.
    fn write_body_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, WriteError<BlockValidationError>> {
        let body_len = checked_body_len(self.payload.len(), 4).map_err(WriteError::Other)?;

        writer.write_u32::<B>(self.pen)?;
        writer.write_all(&self.payload)?;
        Ok(body_len)
    }

    /// Returns the matching typed block variant.
    fn into_block(self) -> Block<'a> {
        if COPIABLE {
            Block::CustomCopiable(CustomBlock {
                pen: self.pen,
                payload: self.payload,
            })
        } else {
            Block::CustomNonCopiable(CustomBlock {
                pen: self.pen,
                payload: self.payload,
            })
        }
    }
}

/* ----- struct CustomBinaryOption ----- */

/// Custom binary option value, excluding its framing and padding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomBinaryOption<'a, const COPIABLE: bool> {
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, [u8]>,
}

impl<'a, const COPIABLE: bool> CustomBinaryOption<'a, COPIABLE> {
    /// Decodes a PEN and binary value from unpadded option content using `B`.
    ///
    /// # Errors
    /// Provide at least four PEN bytes followed by the payload.
    pub fn from_slice<B: ByteOrder>(mut src: &'a [u8]) -> Result<Self, OptionEntryError> {
        let pen = src.read_u32::<B>().map_err(|_| OptionEntryError::WrongSize {
            expected: 4,
            actual: src.len(),
        })?;
        let opt = CustomBinaryOption {
            pen,
            value: Cow::Borrowed(src),
        };
        Ok(opt)
    }

    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomBinaryOption<'static, COPIABLE> {
        CustomBinaryOption {
            pen: self.pen,
            value: Cow::Owned(self.value.into_owned()),
        }
    }
}

impl<'a> CustomBinaryOption<'a, true> {
    /// Converts this option's value into a copiable custom payload type.
    /// Returns `None` if the PEN differs or the decoder does not recognize the format.
    ///
    /// # Errors
    /// Inspect the source error for a recognized payload that cannot be decoded.
    pub fn interpret<T>(&'a self) -> Result<Option<T>, CustomError>
    where
        T: CustomPayloadCopiable<'a> + CustomOptionPayload<'a>,
    {
        if self.pen != T::PEN {
            return Ok(None);
        }

        T::from_slice(&self.value).map_err(|e| CustomError {
            pen: T::PEN,
            src: e.into(),
        })
    }

    /// Converts this option into a [`CommonOption`].
    pub fn into_common_option(self) -> CommonOption<'a> {
        CommonOption::CustomBinaryCopiable(self)
    }
}

impl<'a> CustomBinaryOption<'a, false> {
    /// Converts this option's value into a non-copiable custom payload type.
    /// Returns `None` if the PEN differs or the decoder does not recognize the format.
    ///
    /// # Errors
    /// Inspect the source error for a recognized payload that cannot be decoded.
    pub fn interpret<T>(&'a self, state: &T::State) -> Result<Option<T>, CustomError>
    where
        T: CustomPayloadNonCopiable<'a> + CustomOptionPayload<'a>,
    {
        if self.pen != T::PEN {
            return Ok(None);
        }

        T::from_slice(state, &self.value).map_err(|e| CustomError {
            pen: T::PEN,
            src: e.into(),
        })
    }

    /// Converts this option into a [`CommonOption`].
    pub fn into_common_option(self) -> CommonOption<'a> {
        CommonOption::CustomBinaryNonCopiable(self)
    }
}

/* ----- struct CustomUtf8Option ----- */

/// Custom UTF-8 option value, excluding its framing and padding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomUtf8Option<'a, const COPIABLE: bool> {
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, str>,
}

impl<'a, const COPIABLE: bool> CustomUtf8Option<'a, COPIABLE> {
    /// Decodes a PEN and UTF-8 value from unpadded option content using `B`.
    ///
    /// # Errors
    /// Provide at least four PEN bytes followed by valid UTF-8.
    pub fn from_slice<B: ByteOrder>(mut src: &'a [u8]) -> Result<Self, OptionEntryError> {
        let pen = src.read_u32::<B>().map_err(|_| OptionEntryError::WrongSize {
            expected: 4,
            actual: src.len(),
        })?;
        let opt = CustomUtf8Option {
            pen,
            value: Cow::Borrowed(std::str::from_utf8(src)?),
        };
        Ok(opt)
    }

    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomUtf8Option<'static, COPIABLE> {
        CustomUtf8Option {
            pen: self.pen,
            value: Cow::Owned(self.value.into_owned()),
        }
    }
}
