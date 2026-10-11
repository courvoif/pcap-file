//! Buffered input shared by pcap and pcapng readers.

/* ----- Imports ----- */

use std::io::{Error, ErrorKind, Read};

use crate::{
    pcap::{PcapParseError, PcapReadErrorKind},
    pcapng::errors::{PcapNgParseError, PcapNgReadErrorKind},
};

/* ----- ReadBuffer ----- */

/// Internal structure that buffers its input and allows parsing elements from its buffer.
#[derive(Debug)]
pub(crate) struct ReadBuffer<R: Read> {
    /// Reader from which we read the data from
    reader: R,
    /// Internal buffer
    buffer: Vec<u8>,
    /// Current start position of the buffer
    pos: usize,
    /// Current end position of the buffer
    len: usize,
    /// Total bytes used by the parser
    pub(crate) bytes_used: u64,
}

impl<R: Read> ReadBuffer<R> {
    /// Creates a new ReadBuffer with capacity of 8_000_000
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, 8_000_000)
    }

    /// Creates a new ReadBuffer with the given capacity
    pub fn with_capacity(reader: R, capacity: usize) -> Self {
        Self {
            reader,
            buffer: vec![0_u8; capacity],
            pos: 0,
            len: 0,
            bytes_used: 0,
        }
    }

    /// Parse data from the internal buffer
    ///
    /// Returned values may borrow the buffer after successful parsing.
    ///
    /// # Safety
    /// The parser must not retain input references across incomplete-input retries.
    /// Refilling the buffer invalidates those references before the next attempt.
    pub fn parse_with<'a, 'b: 'a, 'c: 'a, F, O, E>(&'c mut self, mut parser: F) -> Result<O, E::ReadError>
    where
        F: FnMut(&'a [u8]) -> Result<(&'a [u8], O), E>,
        F: 'b,
        O: 'a,
        E: ReadBufferParseError,
    {
        loop {
            let buf = &self.buffer[self.pos..self.len];

            // Sound because 'b and 'c must outlive 'a so the buffer cannot be modified while someone has a ref on it
            let buf: &'a [u8] = unsafe { std::mem::transmute(buf) };

            match parser(buf) {
                Ok((rem, value)) => {
                    self.advance_with_slice(rem);
                    return Ok(value);
                }

                Err(e) if e.is_incomplete() => {
                    // The parsed data len should never be more than the buffer capacity
                    if buf.len() == self.buffer.len() {
                        return Err(E::from_io(Error::from(ErrorKind::UnexpectedEof)));
                    }

                    let nb_read = self.fill_buf().map_err(E::from_io)?;
                    if nb_read == 0 {
                        return Err(E::from_io(Error::from(ErrorKind::UnexpectedEof)));
                    }
                }

                Err(e) => return Err(e.into_read_error()),
            }
        }
    }

    /// Fill the inner buffer.
    /// Copy the remaining data inside buffer at its start and the fill the end part with data from the reader.
    fn fill_buf(&mut self) -> Result<usize, std::io::Error> {
        // Copy the remaining data to the start of the buffer
        let rem_len = unsafe {
            let buf_ptr_mut = self.buffer.as_mut_ptr();
            let rem_ptr_mut = buf_ptr_mut.add(self.pos);
            std::ptr::copy(rem_ptr_mut, buf_ptr_mut, self.len - self.pos);
            self.len - self.pos
        };

        self.pos = 0;
        self.len = rem_len;

        let nb_read = self.reader.read(&mut self.buffer[rem_len..])?;
        self.len += nb_read;

        Ok(nb_read)
    }

    /// Advance the internal buffer position.
    fn advance(&mut self, nb_bytes: usize) {
        assert!(self.pos + nb_bytes <= self.len);
        self.pos += nb_bytes;
        self.bytes_used += nb_bytes as u64;
    }

    /// Advance the internal buffer position.
    fn advance_with_slice(&mut self, rem: &[u8]) {
        // Compute the length between the buffer and the slice
        let diff_len = (rem.as_ptr() as usize)
            .checked_sub(self.buffer().as_ptr() as usize)
            .expect("Rem is not a sub slice of self.buffer");

        self.advance(diff_len)
    }

    /// Return the valid data of the internal buffer
    pub fn buffer(&self) -> &[u8] {
        &self.buffer[self.pos..self.len]
    }

    /// Return true if there is some data that can be read
    pub fn has_data_left(&mut self) -> Result<bool, std::io::Error> {
        // The buffer can be empty and the reader can still have data
        if self.buffer().is_empty() {
            let nb_read = self.fill_buf()?;
            if nb_read == 0 {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Return the inner reader
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Return a reference over the inner reader
    pub fn get_ref(&self) -> &R {
        &self.reader
    }
}

/* ----- ReadBufferParseError ----- */

/// Converts parsing and I/O errors into pcap or pcapng read error causes.
/// Readers attach the packet or block position to each cause.
pub(crate) trait ReadBufferParseError {
    /// Read error cause returned by the buffered parsing loop.
    type ReadError;

    /// Returns true when parsing failed only because more input bytes are needed.
    fn is_incomplete(&self) -> bool;
    /// Converts an I/O error raised while filling the buffer into a read error cause.
    fn from_io(error: Error) -> Self::ReadError;
    /// Converts a terminal parse error into a read error cause.
    fn into_read_error(self) -> Self::ReadError;
}

impl ReadBufferParseError for PcapParseError {
    /// Read error cause for this capture format.
    type ReadError = PcapReadErrorKind;
    /// Returns whether parsing requires more input bytes.
    #[inline]
    fn is_incomplete(&self) -> bool {
        matches!(self, Self::IncompleteBuffer(_, _))
    }

    /// Wraps an I/O error as a capture read error cause.
    #[inline]
    fn from_io(error: Error) -> Self::ReadError {
        PcapReadErrorKind::Io(error)
    }

    /// Converts a terminal parse error into a read error cause.
    #[inline]
    fn into_read_error(self) -> Self::ReadError {
        match self {
            Self::IncompleteBuffer(_, _) => PcapReadErrorKind::Io(Error::from(ErrorKind::UnexpectedEof)),
            Self::Validation(val) => PcapReadErrorKind::Validation(val),
        }
    }
}

impl ReadBufferParseError for PcapNgParseError {
    /// Read error cause for this capture format.
    type ReadError = PcapNgReadErrorKind;
    /// Returns whether parsing requires more input bytes.
    #[inline]
    fn is_incomplete(&self) -> bool {
        matches!(self, Self::IncompleteBuffer(_, _))
    }

    /// Wraps an I/O error as a capture read error cause.
    #[inline]
    fn from_io(error: Error) -> Self::ReadError {
        PcapNgReadErrorKind::Io(error)
    }

    /// Converts a terminal parse error into a read error cause.
    #[inline]
    fn into_read_error(self) -> Self::ReadError {
        self.into()
    }
}
