use std::io::{Read, Result as IoResult, Seek, SeekFrom};

#[derive(Debug)]
pub(crate) struct PeekReader<R: Read> {
    pub inner: R,
    pub peeked: Option<u8>,
}

impl<R: Read> Read for PeekReader<R> {

    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {

        if buf.is_empty() {
            return Ok(0);
        }

        if let Some(b) = self.peeked {

            buf[0] = b;
            self.peeked = None;

            //Read the input and add one to the number of byte read
            self.inner.read(&mut buf[1..]).map(|x| x+1)
        }
        else {
            self.inner.read(buf)
        }
    }
}

impl<R: Read + Seek> Seek for PeekReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> ::std::io::Result<u64> {
        if self.peeked.is_some() {
            self.inner.seek(SeekFrom::Current(-1))?;
            self.peeked = None;
        }
        self.inner.seek(pos)
    }
}

impl<R: Read> PeekReader<R> {

    pub fn new(inner: R) -> PeekReader<R> {
        PeekReader {
            inner,
            peeked: None
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn is_empty(&mut self) -> IoResult<bool> {

        if self.peeked.is_some() {
            return Ok(false);
        }

        let mut buf = [0; 1];
        let nb_read = self.read(&mut buf)?;

        Ok(
            match nb_read {
                0 => true,
                1 => {
                    self.peeked = Some(buf[0]);
                    false
                },
                _ => unreachable!(),
            }
        )
    }
}
