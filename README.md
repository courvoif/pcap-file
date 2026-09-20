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
for pkt in pcap_reader {
    // Check if there is no error
    let pkt = pkt.unwrap();

    // Do something
}
```

The iterator API returns owned packets and is slower than `next_packet()`,
which can borrow packet data directly from the internal read buffer. It stops
after the first error.

### PcapWriter

```rust,no_run
use std::fs::File;
use pcap_file::pcap::{PcapReader, PcapWriter};

let file_in = File::open("test.pcap").expect("Error opening file");
let pcap_reader = PcapReader::new(file_in).unwrap();

let file_out = File::create("out.pcap").expect("Error creating file");
let mut pcap_writer = PcapWriter::with_header(file_out, pcap_reader.header()).unwrap();

for pkt in pcap_reader {
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

Use `next_block()` to borrow typed blocks and access their `PcapNgState`, or
`next_raw_block()` to preserve unknown blocks and inspect undecodable content.

Migration: replace `PcapNgPacket` variant matching with access to its fields.
Block-only `From`/`TryFrom` conversions are replaced by
`PcapNgPacket::from_block(block, state)` (or `block.into_pcapng_packet(state)`),
because resolving the datalink requires interface state.
Non-packet blocks are returned unchanged in `PacketConversionError::NotPacket(block)`;
missing interfaces return `PacketConversionError::InvalidInterfaceId(id)`.
Struct literals must now supply `datalink`.

Standalone block-type constants have been removed.
Import `PcapNgBlock` and use the block type's associated constant, for example
`EnhancedPacketBlock::TYPE` or `CustomBlock::<true>::TYPE`.

`PcapNgWriteError::Validation` now contains only a boxed `ContentValidationError`.
Match `Validation(source)` instead of `Validation { field, source }`;
the separate field-name context has been removed.

Pass `strict: bool` as the last argument to parser, reader, and writer
constructors. For example, `PcapNgReader::new(input, true)` enables semantic
validation; `PcapNgReader::new(input, false)` disables it.
Bounds, framing, and required encoding/decoding conversions are always checked;
option decoding and encoding retain their own checks. Raw operations do not
perform semantic validation: callers can decode a raw block with
`try_into_block(state)` and explicitly call `block.validate(state)`.
Section Header and Interface Description raw blocks are decoded to maintain
state, without semantic validation.

### PcapNgReader packet iterator

```rust,no_run
use std::fs::File;
use pcap_file::pcapng::PcapNgReader;

let file_in = File::open("test.pcapng").expect("Error opening file");
let pcapng_reader = PcapNgReader::new(file_in, true).unwrap();

// Read packets from test.pcapng
for packet in pcapng_reader.packets() {
    // Check if there is no error
    let packet = packet.unwrap();

    // Do something with packet.datalink, packet.timestamp,
    // packet.original_len, and packet.data
}
```

The iterator returns owned packets, skips non-packet blocks, and stops after
the first error. Each packet includes its interface's datalink.
Simple Packet Blocks have no timestamp.
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

More complete read, write, raw recovery, and custom block examples are available
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
