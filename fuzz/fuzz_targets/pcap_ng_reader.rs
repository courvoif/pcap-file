#![no_main]

//! Fuzzes pcapng reader recovery on arbitrary input bytes.

/* ----- Imports ----- */

use libfuzzer_sys::fuzz_target;
use pcap_file::pcapng::PcapNgReader;

/* ----- Fuzz target ----- */

fuzz_target!(|data: &[u8]| {
    if let Ok(mut pcapng_reader) = PcapNgReader::new(data, true) {
        while let Some(_block) = pcapng_reader.next_block() {}
    }
});
