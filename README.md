# pcap-file

Provides parsers, readers and writers for Pcap and PcapNg files.

For Pcap files see the `pcap` module.

For PcapNg files see the `pcapng` module.

[![Crates.io](https://img.shields.io/crates/v/pcap-file.svg)](https://crates.io/crates/pcap-file)
[![rustdoc](https://img.shields.io/badge/Doc-pcap--file-green.svg)](https://docs.rs/pcap-file/)
[![Crates.io](https://img.shields.io/crates/l/pcap-file.svg)](https://github.com/courvoif/pcap-file/blob/master/LICENSE)

## Documentation

<https://docs.rs/pcap-file>

## Installation

This crate is on [crates.io](https://crates.io/crates/pcap-file).
Add it to your `Cargo.toml`:

```toml
[dependencies]
pcap-file = "3.0.0-rc.2"
```

## Examples

### PcapReader

```rust,no_run
use std::fs::File;
use pcap_file::pcap::PcapReader;

let file_in = File::open("test.pcap").expect("Error opening file");
let pcap_reader = PcapReader::new(file_in).unwrap();

// Read test.pcap
for pkt in pcap_reader.packets() {
    // Check if there is no error
    let pkt = pkt.unwrap();

    // Do something
}
```

The iterator API returns owned packets and is slower than `next_packet()`,
which can borrow packet data directly from the internal read buffer. It yields
non-fatal errors and continues when polled again. Fatal errors stop iteration.

### PcapWriter

```rust,no_run
use std::fs::File;
use pcap_file::pcap::{PcapReader, PcapWriter};

let file_in = File::open("test.pcap").expect("Error opening file");
let pcap_reader = PcapReader::new(file_in).unwrap();

let file_out = File::create("out.pcap").expect("Error creating file");
let mut pcap_writer = PcapWriter::with_header(file_out, pcap_reader.header()).unwrap();

for pkt in pcap_reader.packets() {
    pcap_writer.write_packet(&pkt.unwrap()).unwrap();
}
```

### PcapNgReader

```rust,no_run
use std::fs::File;
use pcap_file::pcapng::PcapNgReader;

let file_in = File::open("test.pcapng").expect("Error opening file");
let mut pcapng_reader = PcapNgReader::new(file_in, true).unwrap();

// Read test.pcapng
while let Some(result) = pcapng_reader.next_block() {
    // Check if there is no error
    let (block, state) = result.unwrap();

    // Do something
}
```

Use `next_block()` to borrow typed blocks and access their `PcapNgState`.
After a non-fatal error, the next call continues with the following block.

Use `next_raw_block()` to inspect blocks in their raw representation.

Fatal errors stop the reader. Use `PcapNgReadError::is_fatal()` to distinguish
fatal errors from errors after which reading can continue.

Pass `strict: bool` as the last argument to parser, reader, and writer
constructors for strict validation.

### PcapNgReader packet iterator

```rust,no_run
use std::fs::File;
use pcap_file::pcapng::PcapNgReader;

let file_in = File::open("test.pcapng").expect("Error opening file");
let pcapng_reader = PcapNgReader::new(file_in, true).unwrap();

// Read packets from a valid test.pcapng
for packet in pcapng_reader.packets() {
    // Check if there is no error
    let packet = packet.unwrap();

    // Do something with packet.datalink, packet.timestamp,
    // packet.original_len, and packet.data
}
```

The iterator returns owned packets and skips non-packet blocks. Reading can
continue after non-fatal errors, while fatal errors stop the iterator.
Use `next_block()` when you need interface IDs, options, or other block metadata.

### PcapNgWriter

```rust,no_run
use std::fs::File;
use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};

let file_in = File::open("test.pcapng").expect("Error opening file");
let mut pcapng_reader = PcapNgReader::new(file_in, true).unwrap();

let file_out = File::create("out.pcapng").expect("Error creating file");
let mut pcapng_writer =
    PcapNgWriter::with_section_header(file_out, pcapng_reader.state().section().clone(), true).unwrap();

while let Some(result) = pcapng_reader.next_block() {
    let (block, _) = result.unwrap();
    pcapng_writer.write_block(&block).unwrap();
}
```

Packet blocks in pcapng refer to interface blocks by index. When creating a
pcapng file from scratch, write an `InterfaceDescriptionBlock` before any packet
block that uses that interface.

More complete read, write, raw block, and custom block examples are available
in [`tests/pcap/mod.rs`](tests/pcap/mod.rs) and
[`tests/pcapng/mod.rs`](tests/pcapng/mod.rs).

## Fuzzing

Currently there are 4 crude harnesses to check that the parser won't panic in any situation. To start fuzzing you must install `cargo-fuzz` with the command:

```bash
$ cargo install cargo-fuzz
```

And then, in the root of the repository, you can run the harnesses as:

```bash
$ cargo fuzz run pcap_reader
$ cargo fuzz run pcap_ng_reader
$ cargo fuzz run pcap_parser
$ cargo fuzz run pcap_ng_parser
```

Keep in mind that libfuzzer by default uses only one core, so you can either run all the harnesses in different terminals, or you can pass the `-jobs` and `-workers` attributes. More info can be found in its documentation [here](https://llvm.org/docs/LibFuzzer.html).
To get better crash reports add to you rust flags: `-Zsanitizer=address`.
E.g.

```bash
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run pcap_reader
```

## License

Licensed under MIT.

## Disclaimer

To test the library I used the excellent PcapNg testing suite provided by [hadrielk](https://github.com/hadrielk/pcapng-test-generator).
