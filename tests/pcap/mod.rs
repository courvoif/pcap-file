extern crate pcap_file;

use std::borrow::Cow;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapReader, PcapWriter};
use pcap_file::TsResolution;

static DATA: &[u8; 1455] = include_bytes!("little_endian.pcap");

#[test]
fn read() {
    let mut pcap_reader = PcapReader::new(&DATA[..]).unwrap();

    //Global header len
    let mut data_len = 24;
    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt.unwrap();

        //Packet header len
        data_len += 16;
        data_len += pkt.data.len();
    }

    assert_eq!(data_len, DATA.len());
}

#[test]
fn read_write() {
    let mut pcap_reader = PcapReader::new(&DATA[..]).unwrap();
    let header = pcap_reader.header();

    let mut out = Vec::new();
    let mut pcap_writer = PcapWriter::with_header(out, header).unwrap();

    while let Some(pkt) = pcap_reader.next_packet() {
        pcap_writer.write_packet(&pkt.unwrap()).unwrap();
    }

    out = pcap_writer.into_writer();

    assert_eq!(&DATA[..], &out[..]);
}

#[test]
fn read_write_raw() {
    let mut pcap_reader = PcapReader::new(&DATA[..]).unwrap();
    let header = pcap_reader.header();

    let mut out = Vec::new();
    let mut pcap_writer = PcapWriter::with_header(out, header).unwrap();

    while let Some(pkt) = pcap_reader.next_raw_packet() {
        pcap_writer.write_raw_packet(&pkt.unwrap()).unwrap();
    }

    out = pcap_writer.into_writer();

    assert_eq!(&DATA[..], &out[..]);
}

#[test]
fn big_endian() {
    let data = include_bytes!("big_endian.pcap");

    ////// Global header test //////
    let pcap_header_truth = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 0xFFFF,
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: TsResolution::MicroSecond,
        endianness: pcap_file::Endianness::Big,
    };

    let mut pcap_reader = PcapReader::new(&data[..]).unwrap();
    let pcap_header = pcap_reader.header();

    assert_eq!(pcap_header, pcap_header_truth);

    //// Packet header test ////
    let data_truth = hex::decode(
        "00005e0001b10021280529ba08004500005430a70000ff010348c0a8b1a00a400b3108000afb43a800004\
    fa11b290002538d08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
    )
    .unwrap();

    let pkt_truth = PcapPacket {
        timestamp: Duration::new(1335958313, 152630000),
        orig_len: 98,
        data: Cow::Borrowed(&data_truth[..]),
    };

    let pkt = pcap_reader.next_packet().unwrap().unwrap();

    assert_eq!(pkt.timestamp, pkt_truth.timestamp);
    assert_eq!(pkt.orig_len, pkt_truth.orig_len);
    assert_eq!(pkt.data, pkt_truth.data);
}

#[test]
fn little_endian() {
    let data = include_bytes!("little_endian.pcap");

    ////// Global header test //////
    let pcap_header_truth = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 4096,
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: TsResolution::MicroSecond,
        endianness: pcap_file::Endianness::Little,
    };

    let mut pcap_reader = PcapReader::new(&data[..]).unwrap();
    let pcap_header = pcap_reader.header();

    assert_eq!(pcap_header, pcap_header_truth);

    //// Packet header test ////
    let data_truth = hex::decode("000c29414be70016479df2c2810000780800450000638d2c0000fe06fdc8c0a8e5fec0a8ca4f01bbb4258\
    0e634d3fa9b15fc8018800019da00000101080a130d62b200000000140301000101160301002495776bd4f33faea1aacaf1fbe6026c262fcc2f8cd0f828216dc4aba5bcc1a8e03b496e82").unwrap();

    let pkt_truth = PcapPacket {
        timestamp: Duration::new(1331901000, 0),
        orig_len: 117,
        data: Cow::Borrowed(&data_truth[..]),
    };

    let pkt = pcap_reader.next_packet().unwrap().unwrap();

    assert_eq!(pkt.timestamp, pkt_truth.timestamp);
    assert_eq!(pkt.orig_len, pkt_truth.orig_len);
    assert_eq!(pkt.data, pkt_truth.data);
}
