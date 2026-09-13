//! Custom pcapng blocks and options.
//!
//! [`CustomBlock`] stores vendor-defined block data identified by a Private
//! Enterprise Number (PEN). [`CustomBinaryOption`] and [`CustomUtf8Option`]
//! provide the corresponding custom option representations.
//!
//! Implement [`CustomBlockPayload`] or [`CustomOptionPayload`] together with
//! [`CustomPayloadCopiable`] for self-contained payloads. Use
//! [`CustomPayloadNonCopiable`] when encoding or decoding requires application
//! state.

use std::borrow::Cow;
use std::error::Error;
use std::io::Write;

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::{ReadBytesExt, WriteBytesExt};
use thiserror::Error;

use super::block_common::{Block, PcapNgBlock};
use crate::pcapng::PcapNgState;
use crate::pcapng::blocks::opt_common::CommonOption;
use crate::pcapng::errors::OptionEntryError;
use crate::pcapng::errors::{BlockContentParseError, PcapNgWriteError};

/* ----- traits for Custom Payload ----- */

/// Common interface for copiable custom block and custom option payloads.
///
/// # Examples
///
/// ```
/// use std::convert::Infallible;
/// use std::io::Write;
/// use pcap_file::pcapng::blocks::custom::CustomPayloadCopiable;
///
/// struct Payload(u8);
///
/// impl CustomPayloadCopiable<'_> for Payload {
///     const PEN: u32 = 70_000;
///     type FromSliceError = Infallible;
///     type WriteToError = std::io::Error;
///
///     fn from_slice(slice: &[u8]) -> Result<Option<Self>, Self::FromSliceError> {
///         Ok(slice.first().copied().map(Self))
///     }
///
///     fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Self::WriteToError> {
///         writer.write_all(&[self.0])
///     }
/// }
/// ```
pub trait CustomPayloadCopiable<'a> {
    /// Private Enterprise Number of the entity which defined this payload format.
    const PEN: u32;

    /// Error returned by [`CustomPayloadCopiable::from_slice()`].
    type FromSliceError: Error + Sync + Send + 'static;

    /// Error returned by [`CustomPayloadCopiable::write_to()`].
    type WriteToError: Error + Sync + Send + 'static;

    /// Tries to parse this payload from a byte slice.
    ///
    /// # Errors
    ///
    /// - Returns an error if the payload cannot be decoded.
    fn from_slice(slice: &'a [u8]) -> Result<Option<Self>, Self::FromSliceError>
    where
        Self: Sized;

    /// Writes this payload to a writer.
    ///
    /// # Errors
    ///
    /// - Returns an error if the payload cannot be written.
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Self::WriteToError>;

    /// Serializes this payload into bytes.
    ///
    /// # Important
    /// Do not override.
    ///
    /// # Errors
    ///
    /// - Returns [`CustomError`] if [`CustomPayloadCopiable::write_to`] fails.
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
///
/// # Examples
///
/// ```
/// use std::convert::Infallible;
/// use std::io::Write;
/// use pcap_file::pcapng::blocks::custom::CustomPayloadNonCopiable;
///
/// struct Payload(u8);
///
/// impl CustomPayloadNonCopiable<'_> for Payload {
///     const PEN: u32 = 70_000;
///     type State = u8;
///     type FromSliceError = Infallible;
///     type WriteToError = std::io::Error;
///
///     fn from_slice(state: &Self::State, slice: &[u8]) -> Result<Option<Self>, Self::FromSliceError> {
///         Ok(slice.first().map(|value| Self(value ^ state)))
///     }
///
///     fn write_to<W: Write>(&self, state: &Self::State, writer: &mut W) -> Result<(), Self::WriteToError> {
///         writer.write_all(&[self.0 ^ state])
///     }
/// }
/// ```
pub trait CustomPayloadNonCopiable<'a> {
    /// Private Enterprise Number of the entity which defined this payload format.
    const PEN: u32;

    /// State that may be required to parse/write the payload.
    type State;

    /// Error returned by [`CustomPayloadNonCopiable::from_slice()`].
    type FromSliceError: Error + Sync + Send + 'static;

    /// Error returned by [`CustomPayloadNonCopiable::write_to()`].
    type WriteToError: Error + Sync + Send + 'static;

    /// Tries to parse this payload from a byte slice.
    ///
    /// # Errors
    ///
    /// - Returns an error if the payload cannot be decoded using `state`.
    fn from_slice(state: &Self::State, slice: &'a [u8]) -> Result<Option<Self>, Self::FromSliceError>
    where
        Self: Sized;

    /// Writes this payload to a writer.
    ///
    /// # Errors
    ///
    /// - Returns an error if the payload cannot be written using `state`.
    fn write_to<W: Write>(&self, state: &Self::State, writer: &mut W) -> Result<(), Self::WriteToError>;

    /// Serializes this payload into bytes.
    ///
    /// # Important
    /// Do not override.
    ///
    /// # Errors
    ///
    /// - Returns [`CustomError`] if [`CustomPayloadNonCopiable::write_to`] fails.
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

/// Marker trait for payload types used in custom blocks.
///
/// # Important
/// Implementors must also implement [`CustomPayloadCopiable`] or [`CustomPayloadNonCopiable`].
///
/// # Examples
///
/// ```
/// use pcap_file::pcapng::blocks::custom::CustomBlockPayload;
///
/// struct Payload;
///
/// impl CustomBlockPayload<'_> for Payload {}
/// ```
pub trait CustomBlockPayload<'a> {
    /// Converts this payload into a copiable [`CustomBlock`].
    ///
    /// # Important
    /// Do not override.
    ///
    /// # Errors
    ///
    /// - Returns any error produced by [`CustomPayloadCopiable::to_bytes`].
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

    /// Converts this payload into a non-copiable [`CustomBlock`].
    ///
    /// # Important
    /// Do not override.
    ///
    /// # Errors
    ///
    /// - Returns any error produced by [`CustomPayloadNonCopiable::to_bytes`].
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

/// Marker trait for payload types used in custom options.
///
/// # Important
/// Implementors must also implement [`CustomPayloadCopiable`] or [`CustomPayloadNonCopiable`].
///
/// # Examples
///
/// ```
/// use pcap_file::pcapng::blocks::custom::CustomOptionPayload;
///
/// struct Payload;
///
/// impl CustomOptionPayload<'_> for Payload {}
/// ```
pub trait CustomOptionPayload<'a> {
    /// Converts this payload into a copiable [`CustomBinaryOption`].
    ///
    /// # Important
    /// Do not override.
    ///
    /// # Errors
    ///
    /// - Returns any error produced by [`CustomPayloadCopiable::to_bytes`].
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

    /// Converts this payload into a non-copiable [`CustomBinaryOption`].
    ///
    /// # Important
    /// Do not override.
    ///
    /// # Errors
    ///
    /// - Returns any error produced by [`CustomPayloadNonCopiable::to_bytes`].
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

/// Error produced while converting a custom block or option payload.
#[derive(Debug, Error)]
#[error("Error in custom conversion for PEN {pen:#X}")]
pub struct CustomError {
    /// PEN of the custom block or option.
    pub pen: u32,
    /// Error that caused the conversion to fail.
    #[source]
    pub src: Box<dyn Error + Sync + Send + 'static>,
}

/* ----- struct CustomBlock ----- */

/// Custom Block.
///
/// Stores vendor-defined data identified by a Private Enterprise Number (PEN).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomBlock<'a, const COPIABLE: bool> {
    /// Private Enterprise Number of the entity which defined this block.
    pub pen: u32,
    /// Payload of this block.
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
    ///
    /// Returns [`None`] if this block's PEN does not match [`CustomPayloadCopiable::PEN`]
    /// for `T`.
    ///
    /// # Errors
    ///
    /// - Returns an error if the payload cannot be decoded as `T`.
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
    ///
    /// Returns [`None`] if this block's PEN does not match
    /// [`CustomPayloadNonCopiable::PEN`] for `T`.
    ///
    /// # Errors
    ///
    /// - Returns an error if the payload cannot be decoded as `T` using `state`.
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
    fn from_slice<B: ByteOrder>(
        _state: &PcapNgState,
        mut slice: &'a [u8],
    ) -> Result<(&'a [u8], Self), BlockContentParseError>
    where
        Self: Sized,
    {
        if slice.len() < 4 {
            return Err(BlockContentParseError::BlockContentTooSmall {
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

    fn write_to<B: ByteOrder, W: Write>(
        &self,
        _state: &PcapNgState,
        writer: &mut W,
    ) -> Result<usize, PcapNgWriteError> {
        writer.write_u32::<B>(self.pen)?;
        writer.write_all(&self.payload)?;
        Ok(4 + self.payload.len())
    }

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

/// Custom binary option.
///
/// Stores vendor-defined binary data identified by a Private Enterprise Number (PEN).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomBinaryOption<'a, const COPIABLE: bool> {
    /// Option Private Enterprise Number (PEN).
    pub pen: u32,
    /// Option value.
    pub value: Cow<'a, [u8]>,
}

impl<'a, const COPIABLE: bool> CustomBinaryOption<'a, COPIABLE> {
    /// Parses a [`CustomBinaryOption`] from a byte slice.
    ///
    /// # Errors
    ///
    /// - Returns an error if the option is too short to contain a PEN.
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
    ///
    /// Returns [`None`] if this option's PEN does not match
    /// [`CustomPayloadCopiable::PEN`] for `T`.
    ///
    /// # Errors
    ///
    /// - Returns an error if the value cannot be decoded as `T`.
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
    ///
    /// Returns [`None`] if this option's PEN does not match
    /// [`CustomPayloadNonCopiable::PEN`] for `T`.
    ///
    /// # Errors
    ///
    /// - Returns an error if the value cannot be decoded as `T` using `state`.
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

/// Custom UTF-8 string option.
///
/// Stores vendor-defined UTF-8 data identified by a Private Enterprise Number (PEN).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomUtf8Option<'a, const COPIABLE: bool> {
    /// Option Private Enterprise Number (PEN).
    pub pen: u32,
    /// Option value.
    pub value: Cow<'a, str>,
}

impl<'a, const COPIABLE: bool> CustomUtf8Option<'a, COPIABLE> {
    /// Parses a [`CustomUtf8Option`] from a byte slice.
    ///
    /// # Errors
    ///
    /// - Returns an error if the option is too short to contain a PEN or its
    ///   value is not valid UTF-8.
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

impl<'a> CustomUtf8Option<'a, true> {
    /// Converts this option into a [`CommonOption`].
    pub fn into_common_option(self) -> CommonOption<'a> {
        CommonOption::CustomUtf8Copiable(self)
    }
}

impl<'a> CustomUtf8Option<'a, false> {
    /// Converts this option into a [`CommonOption`].
    pub fn into_common_option(self) -> CommonOption<'a> {
        CommonOption::CustomUtf8NonCopiable(self)
    }
}
