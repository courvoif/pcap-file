#![allow(clippy::unreadable_literal)]

use std::{fs::File, time::Duration};

use pcap_file::pcapng::{PcapNgReader, blocks::interface_description::InterfaceDescriptionOption};

mod pcap;
mod pcapng;


/// Test that the timestamp resolution is correctly read and set in the packets.
#[test]
fn timestamp_resolution() {
    let file = File::open("tests/test_multiple_interfaces.pcapng").unwrap();
    let mut pcapng_reader = PcapNgReader::new(file).unwrap();

    let mut i = 0;
    while let Some(block) = pcapng_reader.next_block() {
        let block = block.unwrap_or_else(|_| panic!("Error on block {i}"));
        
        match i {
            0 => {
                let if_en0 = block.as_interface_description().expect("Block 0 should be an InterfaceDescriptionBlock");
                assert!(matches!(if_en0.options[2], InterfaceDescriptionOption::IfTsResol(9)), "Invalid TsResolution for block 0");
            },
            7=> {
                let if_utun4 = block.as_interface_description().expect("Block 7 should be an InterfaceDescriptionBlock");
                assert_eq!(if_utun4.options[1], InterfaceDescriptionOption::IfTsResol(6), "Invalid TsResolution for block 7");
            },
            8 => {
                let pkt_0 = block.as_enhanced_packet().expect("Block 8 should be an EnhancedPacketBlock");
                assert_eq!(pkt_0.timestamp, Duration::new(1704187433, 103553000), "Invalid timestamp for pkt0");
            },
            10 => {
                let pkt_2 = block.as_enhanced_packet().expect("Block 10 should be an EnhancedPacketBlock");
                assert_eq!(pkt_2.timestamp, Duration::new(1704187, 433132051), "Invalid timestamp for pkt2");
            },
            _ => {}
        }

        i += 1;
    }
}
