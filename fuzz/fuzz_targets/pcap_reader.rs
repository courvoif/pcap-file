#![no_main]

//! Fuzzes classic pcap reader recovery on arbitrary input bytes.

/* ----- Imports ----- */

use libfuzzer_sys::fuzz_target;
use pcap_file::pcap::PcapReader;

/* ----- Fuzz target ----- */

fuzz_target!(|data: &[u8]| {
    if let Ok(mut pcap_reader) = PcapReader::new(data) {
        while let Some(_packet) = pcap_reader.next_packet() {}
    }
});
