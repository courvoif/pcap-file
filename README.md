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

`next_packet()` returns validated packets with timestamps as `Duration`. Use it
when you can process each packet before reading the next one. Its payload
borrows from the reader.

`next_raw_packet()` returns raw packet fields. Use it to inspect or write
`ts_sec`, `ts_frac`, `incl_len`, and `orig_len`, including when validation
fails. Include the payload bytes declared by `incl_len` to read a complete
packet.

`packets()` returns owned, validated packets. Use it for a simple loop or when
you need to retain packets while reading further. Non-fatal errors can be
followed by another iterator poll; fatal errors end iteration.

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

`next_block()` returns typed blocks and the section/interface state. Use it
when you need typed block data. Finish using a block before requesting the
next one. Set `strict: true` to reject semantically invalid blocks other than
Section Header and Interface Description blocks. Set it to `false` to validate
those typed blocks yourself. Section Header and Interface Description blocks
must be valid in either mode.

`next_raw_block()` returns a raw block and the current state. Use it to inspect
raw data or preserve unsupported block types. Use the returned state with
`RawBlock::try_into_block(state)` to decode a block, then with
`Block::validate(state)` to check it. Section Header and Interface Description
blocks must be valid in either mode. After a recoverable block or I/O error,
call the reader again.

Fatal errors stop the reader. Use `PcapNgReadError::is_fatal()` to distinguish
fatal errors from errors after which reading can continue.

Pass `true` as the last argument to pcapng parser, reader, and writer
constructors to enable strict semantic validation.

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

`packets()` returns owned packets from Enhanced, Simple, and obsolete Packet
Blocks. Use it to iterate over packets while skipping non-packet
blocks. Each packet includes its datalink, original length, and data. Simple
Packet Blocks have no timestamp. The iterator uses the reader's `strict`
setting and does not retain metadata such as interface IDs or options. Use
`next_block()` for typed block metadata. Use `next_raw_block()` instead of the
packet iterator to inspect or preserve unsupported block types. Non-fatal
errors can be followed by another iterator poll; fatal errors end iteration.

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

Runnable examples are available under `examples/`. Run one with
`cargo run --example <name>`:

| Example | Demonstrates |
| --- | --- |
| `pcap_parser_packet` | Parse packet records from `tests/pcap/little_endian.pcap` |
| `pcap_reader_packet` | Read packets from `tests/pcap/little_endian.pcap` |
| `pcap_reader_raw_packet` | Inspect raw pcap packet fields and validate them |
| `pcap_reader_iterator` | Iterate over owned pcap packets |
| `pcap_writer_packet` | Write a generated packet to a `Vec<u8>` |
| `pcapng_parser_block` | Parse blocks from `tests/pcapng/little_endian/basic/test001.pcapng` |
| `pcapng_reader_block` | Read typed blocks from the pcapng fixture |
| `pcapng_reader_raw_block` | Inspect raw pcapng blocks and decode them |
| `pcapng_reader_iterator` | Iterate over packets in the pcapng fixture |
| `pcapng_writer_block` | Write generated pcapng blocks to a `Vec<u8>` |
| `pcapng_custom_block` | Write and read a stateful custom block in a new capture |
| `pcapng_custom_options` | Write and read a custom option in a new capture |

Run these commands from the repository root so the examples can read their
fixed test fixtures.
The parser and reader examples continue past errors when the parser or reader
can recover; fatal errors stop the example.
Writer examples generate content and keep output in a `Vec<u8>`. The custom
examples create new captures, read them back, and compare their payloads. Each
custom example defines its payload in the example file. The custom block uses
`PcapNgState` to encode its timestamp with the interface resolution. The custom
option uses it to follow the section byte order.

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
