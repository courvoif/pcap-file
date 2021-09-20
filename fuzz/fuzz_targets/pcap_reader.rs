#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file::PcapReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(pcap_reader) = PcapReader::new(data) {
        for _ in pcap_reader {

        }
    }
});
