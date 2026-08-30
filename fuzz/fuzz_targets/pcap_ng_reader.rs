#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file::pcapng::PcapNgReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut pcapng_reader) = PcapNgReader::new(data) {
        while let Some(Ok(_block)) = pcap_reader.next_packet() {}    }
});
