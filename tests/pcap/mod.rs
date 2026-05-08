extern crate pcap_file;

use std::borrow::Cow;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapReader, PcapValidationError, PcapWriter, RawPcapPacket, TsResolution};

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
        data_len += pkt.len();
    }

    assert_eq!(data_len as usize, DATA.len());
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

    let pkt_truth = PcapPacket::new(Duration::new(1335958313, 152630000), 98, Cow::Borrowed(&data_truth[..])).unwrap();
    let pkt = pcap_reader.next_packet().unwrap().unwrap();

    assert_eq!(pkt.timestamp(), pkt_truth.timestamp());
    assert_eq!(pkt.orig_len(), pkt_truth.orig_len());
    assert_eq!(pkt.data(), pkt_truth.data());
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

    let pkt_truth = PcapPacket::new(Duration::new(1331901000, 0), 117, Cow::Borrowed(&data_truth[..])).unwrap();
    let pkt = pcap_reader.next_packet().unwrap().unwrap();

    assert_eq!(pkt.timestamp(), pkt_truth.timestamp());
    assert_eq!(pkt.orig_len(), pkt_truth.orig_len());
    assert_eq!(pkt.data(), pkt_truth.data());
}

/// Test that parsing an invalid packet doesn't trigger an infinite loop
#[test]
fn infinite_loop() {
    let data = include_bytes!("infinite_loop.pcap");
    let mut pcap_reader = PcapReader::new(&data[..]).unwrap();

    let mut i = 0;
    while let Some(pkt) = pcap_reader.next_packet() {
        let Ok(_) = pkt else {
            break;
        };

        if i > 18 {
            panic!("infinite loop detected");
        }

        i += 1;
    }
}

#[test]
fn reader_with_capacity_handles_large_packets() {
    let data = vec![0xA5; 8_000_001];
    let packet = PcapPacket::new(Duration::new(1, 0), data.len() as u32, Cow::Borrowed(data.as_slice())).unwrap();
    let header = PcapHeader { snaplen: data.len() as u32, ..Default::default() };

    let mut writer = PcapWriter::with_header(Vec::new(), header).unwrap();
    writer.write_packet(&packet).unwrap();
    let pcap = writer.into_writer();

    let mut reader = PcapReader::with_capacity(&pcap[..], pcap.len()).unwrap();
    let packet = reader.next_packet().unwrap().unwrap();

    assert_eq!(packet.len(), data.len() as u32);
    assert_eq!(packet.data(), &data);
    assert!(reader.next_packet().is_none());
}

#[test]
fn raw_reader_recovers_after_typed_packet_validation_error() {
    let packet = RawPcapPacket {
        ts_sec: 1,
        ts_frac: 0,
        incl_len: 4,
        orig_len: 2,
        data: Cow::Borrowed(&[1, 2, 3, 4]),
    };

    let mut writer = PcapWriter::new(Vec::new()).unwrap();
    writer.write_raw_packet(&packet).unwrap();
    let pcap = writer.into_writer();

    let mut reader = PcapReader::new(&pcap[..]).unwrap();
    let typed_error = reader.next_packet().unwrap().unwrap_err();
    assert!(matches!(typed_error, pcap_file::pcap::PcapReadError::Validation(PcapValidationError::OriginLenTooSmall(2, 4))));

    let raw_packet = reader.next_raw_packet().unwrap().unwrap();
    assert_eq!(raw_packet.incl_len, 4);
    assert_eq!(raw_packet.orig_len, 2);
    assert_eq!(&*raw_packet.data, &[1, 2, 3, 4]);
    assert!(reader.next_raw_packet().is_none());
}
