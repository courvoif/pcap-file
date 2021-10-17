use std::io::{Error, ErrorKind, Read};
use crate::PcapError;

const BUF_SIZE: usize = 1_000_000;

#[derive(Debug)]
pub(crate) struct ReadBuffer<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    pos: usize,
    len: usize
}

impl<R: Read> ReadBuffer<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: vec![0_u8; BUF_SIZE],
            pos: 0,
            len: 0
        }
    }

    pub fn fill_buf(&mut self) -> Result<usize, std::io::Error> {
        // Copy the remaining data to the start of the buffer
        let rem_len = unsafe {
            let buf_ptr_mut = self.buffer.as_mut_ptr();
            let rem_ptr_mut = buf_ptr_mut.add(self.pos);
            std::ptr::copy(rem_ptr_mut, buf_ptr_mut, self.len - self.pos);
            self.len - self.pos
        };

        let nb_read = self.reader.read(&mut self.buffer[rem_len..])?;

        self.len = rem_len + nb_read;
        self.pos = 0;

        Ok(nb_read)
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer[self.pos..self.len]
    }

    pub fn advance(&mut self, rem: &[u8]) {
        Self::advance_raw(&self.buffer, &mut self.pos, &mut self.len, rem)
    }

    fn advance_raw(buffer: &[u8], pos: &mut usize, len: &mut usize, slice: &[u8]) {
        // Compute the length between the buffer and the slice
        let diff_len = slice.as_ptr() as usize - buffer.as_ptr() as usize;

        // Assert that the slice is a subslice of the buffer
        assert!(diff_len <= *len);
        assert!(diff_len + slice.len() <= *len);

        *pos = diff_len;
        *len = diff_len + slice.len();
    }

    pub fn parse_with<'a, F, O>(&'a mut self, mut parser: F) -> Result<O, PcapError>
        where F: FnMut(&'a [u8]) -> Result<(&'a [u8], O), PcapError>,
              O: 'a
    {
        loop {
            let buf: &'static [u8] = unsafe{std::mem::transmute(&self.buffer[self.pos..self.len])};
            match parser(buf) {
                Ok((rem, value)) => {
                    Self::advance_raw(&self.buffer, &mut self.pos, &mut self.len, rem);
                    return Ok(value);
                },

                Err(PcapError::IncompleteBuffer(_)) => {
                    let nb_read = self.fill_buf()?;
                    if nb_read == 0 {
                        return Err(PcapError::IoError(Error::from(ErrorKind::UnexpectedEof)));
                    }
                },

                Err(e) => return Err(e)
            }
        }
    }

    /*
    pub fn parse_with_raw<'a, 'b: 'a, F, O>(reader: &mut R, buffer: &'b mut [u8], pos: &mut usize, len: &mut usize, mut parser: F) -> Result<O, PcapError>
        where F: FnMut(&'a [u8]) -> Result<(&'a [u8], O), PcapError>
    {
        loop {
            let buf = &buffer[*pos.. *len];
            match parser(buf) {
                Ok((rem, value)) => {
                    Self::advance_raw(&buffer, pos, len, rem);
                    return Ok(value);
                },

                Err(PcapError::IncompleteBuffer(_)) => {
                    let nb_read = Self::fill_buf_raw(reader, buffer, pos, len)?;
                    if nb_read == 0 {
                        return Err(PcapError::IoError(Error::from(ErrorKind::UnexpectedEof)));
                    }
                },

                Err(e) => return Err(e)
            }
        }
    }
    */

    /*
    pub fn fill_buf_raw(reader: &mut R, buffer: &mut [u8], pos: &mut usize, len: &mut usize) -> Result<usize, std::io::Error> {
        // Copy the remaining data to the start of the buffer
        let (start, rem) = buffer.split_at_mut(*pos);
        start.copy_from_slice(&rem[.. *len]);
        let rem_len = rem.len();

        let nb_read = reader.read(&mut buffer[rem_len..])?;

        *len = rem_len + nb_read;
        *pos = 0;

        Ok(nb_read)
    }*/

    pub fn is_empty(&mut self) -> Result<bool, std::io::Error> {
        // The buffer can be empty and the reader can still have data
        if self.buffer().is_empty() {
            let nb_read = self.fill_buf()?;
            if nb_read == 0 {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}