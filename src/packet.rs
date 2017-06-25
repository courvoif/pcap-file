//! This module contains the `Packet` and the `PacketHeader` structs which represents a packet
//! and its header.

use std::borrow::Cow;
use std::io::{Cursor, Read};

use byteorder::*;

use errors::*;

/// Describes a pcap packet header.
#[derive(Copy, Clone, Default, Debug)]
pub struct PacketHeader {

    /// Timestamp seconds
    pub ts_sec: u32,
    /// Timestamp microseconds
    pub ts_usec: u32,
    /// Number of octets of the packet saved in file
    pub incl_len: u32,
    /// Actual length of the packet
    pub orig_len: u32
}


impl PacketHeader {

    /// Create a new `PacketHeader` with the given parameters.
    ///
    /// Only one length field is provided because incl_len and orig_len are almost always the same.
    pub fn new(ts_sec: u32, ts_usec: u32, len:u32) -> PacketHeader {

        PacketHeader {
            ts_sec: ts_sec,
            ts_usec: ts_usec,
            incl_len: len,
            orig_len: len,
        }
    }

    /// Create a new `PacketHeader` from a given slice.
    pub fn from_slice<B: ByteOrder>(array: &[u8]) -> ResultChain<PacketHeader> {
        PacketHeader::from_reader::<_, B>(&mut Cursor::new(array))
    }

    /// Create a new `PacketHeader` from a given reader.
    pub fn from_reader<R: Read, B: ByteOrder>(reader: &mut R) -> ResultChain<PacketHeader> {

        Ok(
            PacketHeader {

                ts_sec : reader.read_u32::<B>()?,
                ts_usec : reader.read_u32::<B>()?,
                incl_len : reader.read_u32::<B>()?,
                orig_len : reader.read_u32::<B>()?
            }
        )
    }

    /// Convert the `PacketHeader` to a slice of bytes.
    pub fn to_array<B: ByteOrder>(&self) -> ResultChain<Vec<u8>> {

        let mut out = Vec::with_capacity(16);

        out.write_u32::<B>(self.ts_sec)?;
        out.write_u32::<B>(self.ts_usec)?;
        out.write_u32::<B>(self.incl_len)?;
        out.write_u32::<B>(self.orig_len)?;

        Ok(out)
    }
}

/// Describes a pcap packet.
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug)]
pub struct Packet<'a> {

    /// Header of the packet
    pub header: PacketHeader,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>
}


impl<'a> Packet<'a> {

    /// Create a new `Packet` with the given parameters.
    ///
    /// It borrows its payload
    pub fn new(ts_sec: u32, ts_usec: u32, len:u32, data: &'a [u8]) -> Packet<'a> {

        let header = PacketHeader::new(ts_sec, ts_usec, len);

        Packet {
            header: header,
            data: Cow::Borrowed(data)
        }
    }

    /// Create a new `Packet` with the given parameters.
    ///
    /// It owns its payload
    pub fn new_owned(ts_sec: u32, ts_usec: u32, len:u32, data: Vec<u8>) -> Packet<'static> {

        let header = PacketHeader::new(ts_sec, ts_usec, len);

        Packet {
            header: header,
            data: Cow::Owned(data)
        }
    }

    /// Create a new `Packet` from a reader.
    ///
    /// It owns its payload
    pub fn from_reader<R: Read, B: ByteOrder>(reader: &mut R) -> ResultChain<Packet<'static>> {

        let header = PacketHeader::from_reader::<R, B>(reader)?;

        if header.incl_len > 0xFFFF {
            bail!(ErrorKind::BadLength(header.incl_len));
        }

        if header.orig_len > 0xFFFF {
            bail!(ErrorKind::BadLength(header.orig_len));
        }

        let mut bytes = vec![0u8; header.incl_len as usize];
        reader.read_exact(&mut bytes)?;

        Ok(
            Packet {

                header : header,
                data : Cow::Owned(bytes)
            }
        )
    }

    /// Create a new `Packet` from a slice.
    ///
    /// It borrows its payload
    pub fn from_slice<B: ByteOrder>(slice: &[u8]) -> ResultChain<Packet> {

        let mut slice = &slice[..];

        let header = PacketHeader::from_reader::<_, B>(&mut slice)?;

        if header.incl_len > 0xFFFF {
            bail!(ErrorKind::BadLength(header.incl_len));
        }

        if header.orig_len > 0xFFFF {
            bail!(ErrorKind::BadLength(header.orig_len));
        }

        if header.incl_len > slice.len() as u32 {
            bail!(ErrorKind::BufferUnderflow(header.incl_len as u64, slice.len() as u64))
        }

        let len = header.incl_len as usize;
        Ok(
            Packet {

                header : header,
                data : Cow::Borrowed(&slice[0..len as usize])
            }
        )
    }

    /// Convert a borrowed `Packet` to an owned one.
    pub fn into_owned(self) -> Packet<'static> {
        Packet {
            header: self.header.clone(),
            data: Cow::Owned(self.data.into_owned())
        }
    }
}

