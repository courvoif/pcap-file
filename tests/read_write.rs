extern crate pcap_rs;

use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use pcap_rs::{PcapReader, PcapWriter};

static DATA: &'static[u8; 1455] = include_bytes!("test_in.pcap");

#[test]
fn read() {

    let pcap_reader = PcapReader::new(&DATA[..]).unwrap();

    //Global header len
    let mut data_len = 24_usize;
    for pcap in pcap_reader {

        //Packet header len
        data_len += 16;
        data_len += pcap.data.len();
    }

    assert_eq!(data_len, DATA.len());
}

#[test]
fn read_write() {

    let pcap_reader = PcapReader::new(&DATA[..]).unwrap();
    let header = pcap_reader.header;

    let mut out = Vec::new();
    let mut pcap_writer = PcapWriter::with_header(header, out).unwrap();

    for pcap in pcap_reader {
        pcap_writer.write_packet(&pcap).unwrap();
    }

    out = pcap_writer.into_writer();

    assert_eq!(&DATA[..], &out[..]);
}