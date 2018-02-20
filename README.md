[![Crates.io](https://img.shields.io/crates/v/pcap-file.svg)](https://crates.io/crates/pcap-file)
[![rustdoc](https://img.shields.io/badge/Doc-pcap--file-green.svg)](https://docs.rs/pcap-file/)
[![Crates.io](https://img.shields.io/crates/l/pcap-file.svg)](https://github.com/courvoif/pcap-file/blob/master/LICENSE)

# pcap-file
A small crate providing everything you need to read and write pcap files in RUST.

Licensed under MIT.


### Documentation

https://docs.rs/pcap-file


### Installation

This crate is on [crates.io](https://crates.io/crates/pcap-file).
Add it to your `Cargo.toml`:

```toml
[dependencies]
pcap-file = "0.10.0"
```


### Example

```rust
use std::fs::File;
use pcap_file::{PcapReader, PcapWriter};

let file_in = File::open("test.pcap").expect("Error opening file");
let pcap_reader = PcapReader::new(file_in).unwrap();

let file_out = File::create("out.pcap").expect("Error creating file");
let mut pcap_writer = PcapWriter::new(file_out).unwrap();

// Read test.pcap
for pcap in pcap_reader {

    //Check if there is no error
    let pcap = pcap.unwrap();

    //Write each packet of test.pcap in out.pcap
    pcap_writer.write_packet(&pcap).unwrap();
}
```
