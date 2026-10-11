#![no_main]

//! Fuzzes classic pcap parsing at each byte boundary after a recognized capture header.

/* ----- Imports ----- */

use libfuzzer_sys::fuzz_target;
use pcap_file::pcap::PcapParser;

/* ----- Fuzz target ----- */

fuzz_target!(|data: &[u8]| {
    if let Ok((rem, pcap_parser)) = PcapParser::new(data) {
        let mut src = rem;

        while !src.is_empty() {
            let _ = pcap_parser.next_packet(src);
            // Advance even after a parse error to exercise malformed byte boundaries.
            src = &src[1..];
        }
    }
});
