//! Buffered writer flushing and I/O error propagation for both capture formats.

/* ----- Imports ----- */

use std::io::{self, BufWriter, Write};

use pcap_file::pcap::{PcapReader, PcapWriteError, PcapWriter};
use pcap_file::pcapng::errors::PcapNgWriteError;
use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};

/* ----- Buffered output ----- */

/// Makes buffered capture headers available through both writer access APIs after flushing.
#[test]
fn flush_releases_buffered_output() {
    let mut pcap = PcapWriter::new(BufWriter::new(Vec::new())).unwrap();
    assert!(pcap.get_ref().get_ref().is_empty());
    pcap.flush().unwrap();
    let bytes = pcap.get_mut().get_ref();
    PcapReader::new(bytes.as_slice()).unwrap();

    let mut pcapng = PcapNgWriter::new(BufWriter::new(Vec::new()), true).unwrap();
    assert!(pcapng.get_ref().get_ref().is_empty());
    pcapng.flush().unwrap();
    let bytes = pcapng.get_mut().get_ref();
    PcapNgReader::new(bytes.as_slice(), true).unwrap();
}

/* ----- Flush failures ----- */

/// Accepts writes and fails when flushing the output.
struct FlushFailure;

impl Write for FlushFailure {
    /// Accepts the supplied bytes without retaining them.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    /// Reports a flush failure after writes have succeeded.
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush failed"))
    }
}

/// Returns the underlying flush error for both capture formats.
#[test]
fn flush_propagates_io_failures() {
    let mut pcap = PcapWriter::new(FlushFailure).unwrap();
    assert!(matches!(
        pcap.flush(),
        Err(PcapWriteError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));

    let mut pcapng = PcapNgWriter::new(FlushFailure, true).unwrap();
    assert!(matches!(
        pcapng.flush(),
        Err(PcapNgWriteError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
}
