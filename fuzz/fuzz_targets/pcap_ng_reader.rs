#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file::PcapNgReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(pcap_reader) = PcapNgReader::new(data) {
        for maybe_block in pcap_reader {
            if let Ok(block) = maybe_block {
                let _ = block.parsed();
            }
        }
    }
});
