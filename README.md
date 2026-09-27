# pcap-file

Provides parsers, readers and writers for Pcap and PcapNg files.

For Pcap files see the [`pcap`][pcap-module] module.

For PcapNg files see the [`pcapng`][pcapng-module] module.

[![Crates.io][badge-version]][crates-io]
[![rustdoc][badge-rustdoc]][docs-home]
[![License][badge-license]][license]


## Documentation

[API documentation][docs-home]


## Installation

This crate is on [crates.io][crates-io].
Add it to your [`Cargo.toml`][cargo-toml]:

```toml
[dependencies]
pcap-file = "3.0.0-rc.2"
```


## [Pcap][pcap-module]

### [PcapParser][pcap-parser]

[`PcapParser`][pcap-parser] parses a byte slice already in memory. Its
constructor reads the global header and returns the remaining packet data.
Pass that remainder to [`next_packet()`][pcap-parser-next-packet] and replace it
with the returned slice after each packet:

```rust,no_run
use pcap_file::pcap::PcapParser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capture = std::fs::read("tests/pcap/little_endian.pcap")?;
    let (mut remaining, parser) = PcapParser::new(&capture)?;

    while !remaining.is_empty() {
        let (rest, packet) = parser.next_packet(remaining)?;
        println!("{} bytes", packet.len());
        remaining = rest;
    }
    Ok(())
}
```

[`next_packet()`][pcap-parser-next-packet] validates each packet. On a
validation error, use [`next_raw_packet()`][pcap-parser-next-raw-packet] with
the same slice to inspect and skip that packet. If the slice is incomplete,
provide more data before retrying.

### [PcapReader][pcap-reader]

```rust,no_run
use std::fs::File;
use pcap_file::pcap::PcapReader;

let file_in = File::open("test.pcap").expect("Error opening file");
let mut pcap_reader = PcapReader::new(file_in).unwrap();

// Read test.pcap
while let Some(pkt) = pcap_reader.next_packet() {
    // Check if there is no error
    let pkt = pkt.unwrap();

    // Do something
}
```

[`next_packet()`][pcap-reader-next-packet] returns validated packets with
timestamps as [`Duration`][duration]. Use it when you can process each packet
before reading the next one. Its payload borrows from the reader.

[`next_raw_packet()`][pcap-reader-next-raw-packet] returns raw packet fields.
Use it to inspect or write [`ts_sec`][raw-pcap-ts-sec],
[`ts_frac`][raw-pcap-ts-frac], [`incl_len`][raw-pcap-incl-len], and
[`orig_len`][raw-pcap-orig-len], including when validation fails. Include the
payload bytes declared by [`incl_len`][raw-pcap-incl-len] to read a complete
packet.

### [PcapPacketIterator][pcap-packet-iterator]

Call [`PcapReader::packets()`][pcap-reader-packets] to get an iterator over
owned, validated packets. Owned packets can be kept after the iterator
advances:

```rust,no_run
use std::fs::File;
use pcap_file::pcap::PcapReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("tests/pcap/little_endian.pcap")?;
    let reader = PcapReader::new(file)?;

    for result in reader.packets() {
        match result {
            Ok(packet) => println!("{} bytes", packet.len()),
            Err(error) if !error.is_fatal() => eprintln!("recoverable read error: {error}"),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
```

Polling again after a non-fatal error continues the iterator. A fatal error
ends it. See [`pcap_reader_iterator`][ex-pcap-reader-iterator].

### [PcapWriter][pcap-writer]

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


## [PcapNg][pcapng-module]

### [PcapNgParser][pcapng-parser]

[`PcapNgParser`][pcapng-parser] parses a byte slice and tracks the current
section and interfaces. Its constructor reads the first Section Header Block
and returns the remaining block data:

```rust,no_run
use pcap_file::pcapng::PcapNgParser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capture = std::fs::read("tests/pcapng/little_endian/basic/test001.pcapng")?;
    let (mut remaining, mut parser) = PcapNgParser::new(&capture, true)?;

    while !remaining.is_empty() {
        let (rest, block) = parser.next_block(remaining)?;
        println!("block type: {:#010x}", block.type_code());
        remaining = rest;
    }
    Ok(())
}
```

With `strict: true`, [`next_block()`][pcapng-parser-next-block] validates typed
blocks. After a recoverable block decode error,
[`next_raw_block()`][pcapng-parser-next-raw-block] can consume the block from
the same slice so parsing can continue; see
[`pcapng_parser_block`][ex-pcapng-parser-block]. Incomplete input needs more
bytes before retrying.

### [PcapNgReader][pcapng-reader]

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

[`next_block()`][pcapng-reader-next-block] returns typed blocks and the
section/interface state. Use it when you need typed block data. Finish using a
block before requesting the next one. Set `strict: true` to reject semantically
invalid blocks other than Section Header and Interface Description blocks. Set
it to `false` to validate those typed blocks yourself. Section Header and
Interface Description blocks must be valid in either mode.

[`next_raw_block()`][pcapng-reader-next-raw-block] returns a raw block and the
current state. Use it to inspect raw data or preserve unsupported block types.
Use the returned state with
[`RawBlock::try_into_block(state)`][raw-block-try-into-block] to decode a block,
then with [`Block::validate(state)`][block-validate] to check it. Section Header
and Interface Description blocks must be valid in either mode. After a
recoverable block or I/O error, call the reader again.

Fatal errors stop the reader. Use
[`PcapNgReadError::is_fatal()`][pcapng-read-error-is-fatal] to distinguish fatal
errors from errors after which reading can continue.

Pass `true` as the last argument to pcapng parser, reader, and writer
constructors to enable strict semantic validation.

### [PcapNgPacketIterator][pcapng-packet-iterator]

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

[`packets()`][pcapng-reader-packets] returns owned packets from Enhanced,
Simple, and obsolete Packet Blocks. Use it to iterate over packets while
skipping non-packet blocks. Each packet includes its datalink, original length,
and data. Simple Packet Blocks have no timestamp. The iterator uses the
reader's [`strict()`][pcapng-reader-strict] setting and does not retain metadata
such as interface IDs or options. Use
[`next_block()`][pcapng-reader-next-block] for typed block metadata.
Use [`next_raw_block()`][pcapng-reader-next-raw-block] instead of the
packet iterator to inspect or preserve unsupported block types. Non-fatal
errors can be followed by another iterator poll; fatal errors end iteration.

### [PcapNgWriter][pcapng-writer]

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
pcapng file from scratch, write an
[`InterfaceDescriptionBlock`][interface-description-block] before any packet
block that uses that interface.

### [Custom blocks and options][custom-module]

Implement [`CustomPayloadNonCopiable`][custom-payload-non-copiable] on a payload
type, together with [`CustomBlockPayload`][custom-block-payload] for a custom
block or [`CustomOptionPayload`][custom-option-payload] for a custom option.


## [Examples][examples-directory]

Run an example from the repository root with `cargo run --example <name>`.
Parser and reader examples use fixed captures under [`tests/`][tests-directory].
They continue after recoverable errors and stop on fatal ones. Writers keep
their output in a [`Vec<u8>`][vec]. Example names link to their source on GitHub;
API names link to relative rustdoc pages for the crate version being viewed.

### [Pcap examples][examples-directory]

- [`pcap_parser_packet`][ex-pcap-parser-packet]
  uses [`PcapParser`][pcap-parser]
  to parse packets from a byte slice. On validation errors, it uses raw parsing
  to skip the packet.
- [`pcap_reader_packet`][ex-pcap-reader-packet]
  uses [`PcapReader`][pcap-reader]
  to read validated packets one at a time and handle recoverable read errors.
- [`pcap_reader_raw_packet`][ex-pcap-reader-raw-packet]
  uses [`PcapReader`][pcap-reader]
  to inspect raw timestamp and length fields, then validate each packet.
- [`pcap_reader_iterator`][ex-pcap-reader-iterator]
  uses [`PcapPacketIterator`][pcap-packet-iterator]
  to iterate over owned packets and continue after non-fatal errors.
- [`pcap_writer_packet`][ex-pcap-writer-packet]
  uses [`PcapWriter`][pcap-writer]
  to write a generated packet to an in-memory capture.

### [Pcapng examples][examples-directory]

- [`pcapng_parser_block`][ex-pcapng-parser-block]
  uses [`PcapNgParser`][pcapng-parser]
  to parse typed blocks from a byte slice. Raw parsing skips undecodable blocks.
- [`pcapng_reader_block`][ex-pcapng-reader-block]
  uses [`PcapNgReader`][pcapng-reader]
  to read typed blocks alongside the current section and interface state.
- [`pcapng_reader_raw_block`][ex-pcapng-reader-raw-block]
  uses [`PcapNgReader`][pcapng-reader]
  to inspect raw block fields, then decode and validate each block.
- [`pcapng_reader_iterator`][ex-pcapng-reader-iterator]
  uses [`PcapNgPacketIterator`][pcapng-packet-iterator]
  to iterate over owned packets while skipping non-packet blocks.
- [`pcapng_writer_block`][ex-pcapng-writer-block]
  uses [`PcapNgWriter`][pcapng-writer]
  to write a generated interface and packet block to an in-memory capture.
- [`pcapng_custom_block`][ex-pcapng-custom-block]
  implements [`CustomBlockPayload`][custom-block-payload]
  with a timestamp encoded using interface state, then reads it back.
- [`pcapng_custom_options`][ex-pcapng-custom-options]
  implements [`CustomOptionPayload`][custom-option-payload]
  with a value encoded using the section byte order, then reads it back.

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

Keep in mind that libfuzzer by default uses only one core, so you can either run all the harnesses in different terminals, or you can pass the `-jobs` and `-workers` attributes. More info can be found in its [documentation][libfuzzer].
To get better crash reports add to you rust flags: `-Zsanitizer=address`.
E.g.

```bash
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run pcap_reader
```

## License

Licensed under MIT.

## Disclaimer

To test the library I used the excellent PcapNg testing suite provided by [hadrielk][pcapng-test-generator].

<!-- API documentation -->

[pcap-module]: pcap/index.html
[pcap-parser]: pcap/struct.PcapParser.html
[pcap-parser-next-packet]: pcap/struct.PcapParser.html#method.next_packet
[pcap-parser-next-raw-packet]: pcap/struct.PcapParser.html#method.next_raw_packet
[pcap-reader]: pcap/struct.PcapReader.html
[pcap-reader-next-packet]: pcap/struct.PcapReader.html#method.next_packet
[pcap-reader-next-raw-packet]: pcap/struct.PcapReader.html#method.next_raw_packet
[pcap-reader-packets]: pcap/struct.PcapReader.html#method.packets
[pcap-packet-iterator]: pcap/struct.PcapPacketIterator.html
[pcap-writer]: pcap/struct.PcapWriter.html
[raw-pcap-ts-sec]: pcap/struct.RawPcapPacket.html#structfield.ts_sec
[raw-pcap-ts-frac]: pcap/struct.RawPcapPacket.html#structfield.ts_frac
[raw-pcap-incl-len]: pcap/struct.RawPcapPacket.html#structfield.incl_len
[raw-pcap-orig-len]: pcap/struct.RawPcapPacket.html#structfield.orig_len
[pcapng-module]: pcapng/index.html
[pcapng-parser]: pcapng/struct.PcapNgParser.html
[pcapng-parser-next-block]: pcapng/struct.PcapNgParser.html#method.next_block
[pcapng-parser-next-raw-block]: pcapng/struct.PcapNgParser.html#method.next_raw_block
[pcapng-reader]: pcapng/struct.PcapNgReader.html
[pcapng-reader-next-block]: pcapng/struct.PcapNgReader.html#method.next_block
[pcapng-reader-next-raw-block]: pcapng/struct.PcapNgReader.html#method.next_raw_block
[pcapng-reader-packets]: pcapng/struct.PcapNgReader.html#method.packets
[pcapng-reader-strict]: pcapng/struct.PcapNgReader.html#method.strict
[pcapng-packet-iterator]: pcapng/struct.PcapNgPacketIterator.html
[pcapng-writer]: pcapng/struct.PcapNgWriter.html
[pcapng-read-error-is-fatal]: pcapng/errors/enum.PcapNgReadError.html#method.is_fatal
[raw-block-try-into-block]: pcapng/blocks/block_common/struct.RawBlock.html#method.try_into_block
[block-validate]: pcapng/blocks/block_common/enum.Block.html#method.validate
[interface-description-block]: pcapng/blocks/interface_description/struct.InterfaceDescriptionBlock.html
[custom-payload-non-copiable]: pcapng/blocks/custom/trait.CustomPayloadNonCopiable.html
[custom-module]: pcapng/blocks/custom/index.html
[custom-block-payload]: pcapng/blocks/custom/trait.CustomBlockPayload.html
[custom-option-payload]: pcapng/blocks/custom/trait.CustomOptionPayload.html
[duration]: https://doc.rust-lang.org/std/time/struct.Duration.html
[vec]: https://doc.rust-lang.org/std/vec/struct.Vec.html

<!-- Example source and other resources -->

[examples-directory]: https://github.com/courvoif/pcap-file/tree/master/examples
[ex-pcap-parser-packet]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_parser_packet.rs
[ex-pcap-reader-packet]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_reader_packet.rs
[ex-pcap-reader-raw-packet]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_reader_raw_packet.rs
[ex-pcap-reader-iterator]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_reader_iterator.rs
[ex-pcap-writer-packet]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_writer_packet.rs
[ex-pcapng-parser-block]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_parser_block.rs
[ex-pcapng-reader-block]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_reader_block.rs
[ex-pcapng-reader-raw-block]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_reader_raw_block.rs
[ex-pcapng-reader-iterator]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_reader_iterator.rs
[ex-pcapng-writer-block]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_writer_block.rs
[ex-pcapng-custom-block]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_custom_block.rs
[ex-pcapng-custom-options]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_custom_options.rs
[badge-version]: https://img.shields.io/crates/v/pcap-file.svg
[badge-rustdoc]: https://img.shields.io/badge/Doc-pcap--file-green.svg
[badge-license]: https://img.shields.io/crates/l/pcap-file.svg
[crates-io]: https://crates.io/crates/pcap-file
[docs-home]: https://docs.rs/pcap-file/
[license]: https://github.com/courvoif/pcap-file/blob/master/LICENSE
[cargo-toml]: https://github.com/courvoif/pcap-file/blob/master/Cargo.toml
[tests-directory]: https://github.com/courvoif/pcap-file/tree/master/tests
[libfuzzer]: https://llvm.org/docs/LibFuzzer.html
[pcapng-test-generator]: https://github.com/hadrielk/pcapng-test-generator
