use std::io::{Error, ErrorKind, Read};

use crate::{
    pcap::{PcapParseError, PcapReadError},
    pcapng::errors::{PcapNgParseError, PcapNgReadError},
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
    /// Creates a new `ReadBuffer` with a default capacity of 8 MB.
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, 8_000_000)
    }

    /// Creates a new `ReadBuffer` with the given capacity.
    pub fn with_capacity(reader: R, capacity: usize) -> Self {
        Self {
            reader,
            buffer: vec![0_u8; capacity],
            pos: 0,
            len: 0,
            bytes_used: 0,
        }
    }

    /// Parses data from the internal buffer.
    ///
    /// Safety
    ///
    /// The parser must NOT keep a reference to the buffer in input.
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
                    // A buffer extension is needed but the buffer is already full
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
        let new_len = unsafe {
            if self.pos != 0 {
                let buf_ptr_mut = self.buffer.as_mut_ptr();
                let rem_ptr_mut = buf_ptr_mut.add(self.pos);
                std::ptr::copy(rem_ptr_mut, buf_ptr_mut, self.len - self.pos);
            }

            self.len - self.pos
        };

        // Update the buffer boundaries with the temporary values to
        // prevent an invalid state if the next read fails
        self.pos = 0;
        self.len = new_len;

        let nb_read = self.reader.read(&mut self.buffer[new_len..])?;
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

    /// Returns the valid data in the internal buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer[self.pos..self.len]
    }

    /// Returns whether data remains to be read.
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

    /// Returns the inner reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Returns a reference to the inner reader.
    pub fn get_ref(&self) -> &R {
        &self.reader
    }
}

/* ----- ReadBufferParseError ----- */

/// Adapter used by [`ReadBuffer::parse_with`] to share the buffered parsing loop
/// between pcap and pcapng parsers while preserving their read error types.
pub(crate) trait ReadBufferParseError {
    /// Read-level error returned by the reader using this parse error.
    type ReadError;

    /// Returns true when parsing failed only because more input bytes are needed.
    fn is_incomplete(&self) -> bool;
    /// Converts an I/O error raised while filling the buffer into the read error.
    fn from_io(error: Error) -> Self::ReadError;
    /// Converts a terminal parse error into the read error returned to callers.
    fn into_read_error(self) -> Self::ReadError;
}

impl ReadBufferParseError for PcapParseError {
    type ReadError = PcapReadError;

    #[inline]
    fn is_incomplete(&self) -> bool {
        matches!(self, Self::IncompleteBuffer(_, _))
    }

    #[inline]
    fn from_io(error: Error) -> Self::ReadError {
        PcapReadError::Io(error)
    }

    #[inline]
    fn into_read_error(self) -> Self::ReadError {
        match self {
            Self::IncompleteBuffer(_, _) => PcapReadError::Io(Error::from(ErrorKind::UnexpectedEof)),
            Self::Validation(val) => PcapReadError::Validation(val),
        }
    }
}

impl ReadBufferParseError for PcapNgParseError {
    type ReadError = PcapNgReadError;

    #[inline]
    fn is_incomplete(&self) -> bool {
        matches!(self, Self::IncompleteBuffer(_, _))
    }

    #[inline]
    fn from_io(error: Error) -> Self::ReadError {
        PcapNgReadError::Io(error)
    }

    #[inline]
    fn into_read_error(self) -> Self::ReadError {
        self.into()
    }
}

#[cfg(test)]
mod test {
    use std::io::{Error, ErrorKind, Read};

    use byteorder_slice::option::ReadSlice;

    use crate::pcap::{PcapParseError, PcapReadError};

    /// Fake reader that returns two data chunks separated by a transient I/O error.
    #[derive(Debug, Default)]
    struct FailOnceReader {
        read_count: usize,
    }

    impl Read for FailOnceReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let result = match self.read_count {
                0 => {
                    buf[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
                    Ok(6)
                }
                1 => Err(Error::other("injected read failure")),
                2 => {
                    buf[..4].copy_from_slice(&[1, 2, 3, 4]);
                    Ok(4)
                }
                _ => unreachable!(),
            };

            self.read_count += 1;
            result
        }
    }

    /// Parsing function that always parses 4B.
    fn parse_4_bytes(mut src: &[u8]) -> Result<(&[u8], &[u8]), PcapParseError> {
        src.read_slice(4)
            .map(|slice| (src, slice))
            .ok_or(PcapParseError::IncompleteBuffer(4, src.len()))
    }

    /// Checks that buffered data is preserved when an I/O error interrupts a
    /// refill and that parsing can resume successfully on the next attempt.
    #[test]
    fn parse_with_can_retry_after_io_error() {
        let mut reader = super::ReadBuffer::with_capacity(FailOnceReader::default(), 6);

        // Consume four bytes from the first chunk, leaving [5, 6] buffered.
        let first = reader.parse_with(|buf| parse_4_bytes(buf)).expect("1st read failed");
        assert_eq!(first, [1, 2, 3, 4]);

        // Parsing the next value requires a refill. The buffer is compacted
        // before the underlying reader returns its injected error.
        let second = reader
            .parse_with(|buf| parse_4_bytes(buf))
            .expect_err("2nd read didn't fail");
        assert!(matches!(second, PcapReadError::Io(error) if error.kind() == ErrorKind::Other));

        // A retry must preserve the two compacted bytes and append new input.
        let third = reader.parse_with(|buf| parse_4_bytes(buf)).expect("3rd read failed");
        assert_eq!(third, [5, 6, 1, 2]);
    }

    // Shouldn't compile
    // #[test]
    // fn parse_with_safety() {
    //     let a = &[0_u8; 10];
    //     let b = &mut &a[..];
    //
    //     let input = vec![1_u8; 100];
    //     let input_read = &mut &input[..];
    //     let mut reader = super::ReadBuffer::new(input_read);
    //
    //     unsafe {
    //         reader.parse_with(|buf| {
    //             *b = buf;
    //             Ok((buf, ()))
    //         });
    //     }
    //
    //     unsafe {
    //         reader.has_data_left();
    //     }
    //
    //     println!("{:?}", b);
    // }
}
