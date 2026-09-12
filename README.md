# pcap-file

Provides parsers, readers, and writers for pcap and pcapng files.

For pcap files, see the [`pcap`] module, especially [`PcapParser`],
[`PcapReader`], [`PcapPacketIterator`] and [`PcapWriter`].

For pcapng files, see the [`pcapng`] module, especially [`PcapNgParser`],
[`PcapNgReader`], [`PcapNgPacketIterator`] and [`PcapNgWriter`].

Format-specific error types are available in [`pcap::errors`] and
[`pcapng::errors`].

[![Crates.io](https://img.shields.io/crates/v/pcap-file)](https://crates.io/crates/pcap-file/3.0.0-rc.3)
[![Docs](https://img.shields.io/docsrs/pcap-file)](https://docs.rs/pcap-file/latest/pcap_file/)
[![License](https://img.shields.io/crates/l/pcap-file)](https://github.com/courvoif/pcap-file/blob/master/LICENSE)

## Documentation

<https://docs.rs/pcap-file>

## Installation

This crate is on [crates.io](https://crates.io/crates/pcap-file).
Add it to your `Cargo.toml`:

```toml
[dependencies]
pcap-file = "3.0.0-rc.3"
```

## Pcap

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

The iterator API returns owned packets, stops after the first error, and is
slower than [`PcapReader::next_packet`], which can borrow packet data directly
from the internal read buffer.
After an unrecoverable reading error, callers should discard the reader. Use
[`PcapReader::next_raw_packet`] from the outset when malformed packet content
must be handled; see the [raw-reading example][pcap-read-raw].

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

## Pcapng

### PcapNgReader

```rust,no_run
use std::fs::File;
use pcap_file::pcapng::PcapNgReader;

let file_in = File::open("test.pcapng").expect("Error opening file");
let pcapng_reader = PcapNgReader::new(file_in).unwrap();

// Read test.pcapng
for packet in pcapng_reader {
    // Check if there is no error
    let packet = packet.unwrap();

    // Do something
}
```

The iterator API is intended for simple packet traversal: it skips non-packet
blocks, returns owned packets, does not expose [`PcapNgState`], and stops after
the first error. Use [`PcapNgReader::next_block`] when processing a block
requires the current state; it returns borrowed blocks and the state after
applying that block.
Use [`PcapNgReader::state`] to inspect the current section or interfaces
outside that reading loop. The parser and writer provide equivalent `state()`
accessors.
After an unrecoverable reading error, callers should discard the reader. Use
[`PcapNgReader::next_raw_block`] from the outset when malformed block content
must be handled; see the [raw-reading example][pcapng-read-raw].
The slice-based [`PcapNgParser`] leaves cursor management to the caller: after
a recoverable typed conversion error, call
[`PcapNgParser::next_raw_block`] with the same input slice.

### PcapNgWriter

```rust,no_run
use std::fs::File;
use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};

let file_in = File::open("test.pcapng").expect("Error opening file");
let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();

let file_out = File::create("out.pcapng").expect("Error creating file");
let mut pcapng_writer =
    PcapNgWriter::with_section_header(file_out, pcapng_reader.state().section().clone()).unwrap();

while let Some(block) = pcapng_reader.next_block() {
    let (block, _) = block.unwrap();
    pcapng_writer.write_block(&block).unwrap();
}
```

Packet blocks in pcapng refer to interface blocks by index. When creating a
pcapng file from scratch, write an [`InterfaceDescriptionBlock`] before any
packet block that uses that interface.

## Examples

Runnable examples are available in the [examples on GitHub][examples]:

- Pcap: [parse][pcap-parse], [read][pcap-read], and
  [create and write a packet][pcap-write]. See also how to
  [read and handle raw packets][pcap-read-raw].
- pcapng: [parse][pcapng-parse], [read][pcapng-read], and
  [create and write a packet][pcapng-write]. See also how to
  [read and handle raw blocks][pcapng-read-raw].
- pcapng extensions: read and write a
  [custom block][pcapng-custom-block] or a
  [custom option][pcapng-custom-option].
  Both examples propagate conversion errors and distinguish payloads registered
  under a different PEN.

Run an example from the repository root. Standard read and parse examples use
bundled test captures, raw-reading examples generate one malformed record, and
write examples create a fixed example file under `target/`:

```bash
cargo run --example pcap_read
cargo run --example pcapng_parse
cargo run --example pcap_read_raw
cargo run --example pcapng_read_raw
```

## Fuzzing

Four fuzzing harnesses check that the parsers do not panic on arbitrary input.

Install `cargo-fuzz` with:

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
To get better crash reports, add `-Zsanitizer=address` to your Rust flags.
For example:

```bash
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run pcap_reader
```

## License

Licensed under MIT.

## Disclaimer

The test suite uses the pcapng files provided by [hadrielk's pcapng test generator](https://github.com/hadrielk/pcapng-test-generator).

[examples]: https://github.com/courvoif/pcap-file/tree/master/examples
[pcap-parse]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_parse.rs
[pcap-read]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_read.rs
[pcap-write]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_write.rs
[pcap-read-raw]: https://github.com/courvoif/pcap-file/blob/master/examples/pcap_read_raw.rs
[pcapng-parse]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_parse.rs
[pcapng-read]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_read.rs
[pcapng-write]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_write.rs
[pcapng-read-raw]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_read_raw.rs
[pcapng-custom-block]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_custom_block.rs
[pcapng-custom-option]: https://github.com/courvoif/pcap-file/blob/master/examples/pcapng_custom_option.rs

[`pcap`]: crate::pcap
[`pcap::errors`]: crate::pcap::errors
[`pcapng`]: crate::pcapng
[`pcapng::errors`]: crate::pcapng::errors
[`PcapParser`]: crate::pcap::PcapParser
[`PcapReader`]: crate::pcap::PcapReader
[`PcapReader::next_packet`]: crate::pcap::PcapReader::next_packet
[`PcapReader::next_raw_packet`]: crate::pcap::PcapReader::next_raw_packet
[`PcapPacketIterator`]: crate::pcap::PcapPacketIterator
[`PcapWriter`]: crate::pcap::PcapWriter
[`PcapNgParser`]: crate::pcapng::PcapNgParser
[`PcapNgParser::next_raw_block`]: crate::pcapng::PcapNgParser::next_raw_block
[`PcapNgReader`]: crate::pcapng::PcapNgReader
[`PcapNgReader::next_block`]: crate::pcapng::PcapNgReader::next_block
[`PcapNgReader::next_raw_block`]: crate::pcapng::PcapNgReader::next_raw_block
[`PcapNgReader::state`]: crate::pcapng::PcapNgReader::state
[`PcapNgPacketIterator`]: crate::pcapng::PcapNgPacketIterator
[`PcapNgWriter`]: crate::pcapng::PcapNgWriter
[`PcapNgState`]: crate::pcapng::PcapNgState
[`InterfaceDescriptionBlock`]: crate::pcapng::blocks::interface_description::InterfaceDescriptionBlock
