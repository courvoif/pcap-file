#![no_main]

//! Fuzzes pcapng parsing at each byte boundary after a recognized capture header.

/* ----- Imports ----- */

use libfuzzer_sys::fuzz_target;
use pcap_file::pcapng::PcapNgParser;

/* ----- Fuzz target ----- */

fuzz_target!(|data: &[u8]| {
    if let Ok((rem, mut pcapng_parser)) = PcapNgParser::new(data, true) {
        let mut src = rem;

        while !src.is_empty() {
            let _ = pcapng_parser.next_block(src);
            // Advance even after a parse error to exercise malformed byte boundaries.
            src = &src[1..];
        }
    }
});
