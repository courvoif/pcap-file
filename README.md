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
let pcapng_reader = PcapNgReader::new(file_in).unwrap();

// Read test.pcapng
for block in pcapng_reader {
    // Check if there is no error
    let block = block.unwrap();

    // Do something
}
```

The iterator API is intended for simple traversal: it returns owned blocks,
does not expose `PcapNgState`, and stops after the first error. Use
`next_block()` when processing a block requires the current state; it returns
borrowed blocks and the state after applying that block. Some typed conversion
errors returned by `next_block()` can be recovered by reading the same block
with `next_raw_block()`; see the [raw recovery example](examples/pcapng_raw_recovery.rs).
The same recovery pattern applies to `PcapNgParser`: after a recoverable typed
conversion error, call `next_raw_block()` with the same input slice.

### PcapNgWriter

```rust,no_run
use std::fs::File;
use pcap_file::pcapng::{PcapNgReader, PcapNgWriter};

let file_in = File::open("test.pcapng").expect("Error opening file");
let pcapng_reader = PcapNgReader::new(file_in).unwrap();

let file_out = File::create("out.pcapng").expect("Error creating file");
let mut pcapng_writer =
    PcapNgWriter::with_section_header(file_out, pcapng_reader.section().clone()).unwrap();

for block in pcapng_reader {
    let block = block.unwrap();
    pcapng_writer.write_block(&block).unwrap();
}
```

Packet blocks in pcapng refer to interface blocks by index. When creating a
pcapng file from scratch, write an `InterfaceDescriptionBlock` before any packet
block that uses that interface.

Runnable examples are available in the [`examples`](examples) directory:

- Pcap: [parse](examples/pcap_parse.rs), [read](examples/pcap_read.rs), and
  [create and write a packet](examples/pcap_write.rs). See also how to
  [recover a malformed packet as raw data](examples/pcap_raw_recovery.rs).
- PcapNg: [parse](examples/pcapng_parse.rs), [read](examples/pcapng_read.rs), and
  [create and write a packet](examples/pcapng_write.rs). See also how to
  [recover a malformed block as raw data](examples/pcapng_raw_recovery.rs).
- PcapNg extensions: read and write a [custom block](examples/pcapng_custom_block.rs)
  or a [custom option](examples/pcapng_custom_option.rs). Both examples propagate
  conversion errors and distinguish payloads registered under a different PEN.

Run an example from the repository root. Read and parse examples use bundled
test captures, recovery examples generate one malformed record, and write
examples create a uniquely named file under `target/`:

```bash
cargo run --example pcap_read
cargo run --example pcapng_parse
cargo run --example pcap_raw_recovery
cargo run --example pcapng_raw_recovery
```

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
