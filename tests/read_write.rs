extern crate pcap_file;

use pcap_file::{PcapReader, PcapWriter};

static DATA: &'static[u8; 1455] = include_bytes!("little_endian.pcap");

#[test]
fn read() {

    let pcap_reader = PcapReader::new(&DATA[..]).unwrap();

    //Global header len
    let mut data_len = 24;
    for pcap in pcap_reader {

        let pcap = pcap.unwrap();

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
        pcap_writer.write_packet(&pcap.unwrap()).unwrap();
    }

    out = pcap_writer.into_writer();

    assert_eq!(&DATA[..], &out[..]);
}

#[test]
fn big_endian() {

    let data  = include_bytes!("big_endian.pcap");

    //Global header test
    let mut pcap_reader = PcapReader::new(&data[..]).unwrap();
    let header = pcap_file::PcapHeader {
        magic_number: 0xa1b2c3d4,
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 0xffff,
        datalink: pcap_file::DataLink::ETHERNET,
    };

    assert_eq!(pcap_reader.header, header);
    assert_eq!(pcap_reader.header.endianness(), pcap_file::Endianness::Big);

    //Packet header test
    let packet = pcap_reader.next().unwrap().unwrap();
    let pkt_hdr = pcap_file::PacketHeader {
        ts_sec: 0x4fa11b29,
        ts_usec: 0x00025436,
        incl_len: 0x62,
        orig_len: 0x62,
    };

    assert_eq!(packet.header, pkt_hdr);
}

#[test]
fn little_endian() {

    let data  = include_bytes!("little_endian.pcap");

    //Global header test
    let mut pcap_reader = PcapReader::new(&data[..]).unwrap();
    let header = pcap_file::PcapHeader {
        magic_number: 0xd4c3b2a1,
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 0x1000,
        datalink: pcap_file::DataLink::ETHERNET,
    };

    assert_eq!(pcap_reader.header, header);
    assert_eq!(pcap_reader.header.endianness(), pcap_file::Endianness::Little);

    //Packet header test
    let packet = pcap_reader.next().unwrap().unwrap();
    let pkt_hdr = pcap_file::PacketHeader {
        ts_sec: 0x4f633248,
        ts_usec: 0x0,
        incl_len: 0x75,
        orig_len: 0x75,
    };

    assert_eq!(packet.header, pkt_hdr);
}