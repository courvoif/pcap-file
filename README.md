# pcap-file

Parse, read, and write [Pcap][pcap-module] and [PcapNg][pcapng-module] capture files in Rust.

[![Crates.io][badge-version]][crates-io]
[![rustdoc][badge-rustdoc]][docs-home]
[![License][badge-license]][license]

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
pcap-file = "3.0.0-rc.3"
```

Run any [example][examples-directory] linked below with
`cargo run --example <name>` from the repository root.

## Common API guidance

### Input and ownership

- **Input:** Parsers accept byte slices; readers accept [`Read`][std-read] sources;
  writers accept [`Write`][std-write] destinations.
- **Parser progress:** Pass the returned remaining slice to the next call.
  For incomplete input, supply more bytes and retry with the unconsumed input.
- **Borrowed data:** Finish using a reader's packet or block before the next read.
- **Owned packets:** Consume the reader with [`PcapReader::packets()`][pcap-reader-packets]
  or [`PcapNgReader::packets()`][pcapng-reader-packets] to retain packets after advancing.

### Errors and buffers

- **Recovery:** Use [`PcapReadError::is_fatal()`][pcap-read-error-is-fatal] or
  [`PcapNgReadError::is_fatal()`][pcapng-read-error-is-fatal] before reading or polling again.
  After a fatal error, later calls return [`None`][std-none].
- **Rejected records:** Readers consume records rejected during ordinary validation.
  Choose raw reading from the start if you need to inspect them.
- **Capacity:** Readers use a fixed `8_000_000`-byte buffer.
  Use [`PcapReader::with_capacity`][pcap-reader-with-capacity] or
  [`PcapNgReader::with_capacity`][pcapng-reader-with-capacity] for larger records, including framing and the initial header.
  Records exceeding capacity produce a fatal [`UnexpectedEof`][std-unexpected-eof] error.
- **Output failures:** An I/O failure while writing can leave partial output.
  Repair or discard it.

## [Pcap][pcap-module]

### Choosing an API

| API | Use it to | Example |
| --- | --- | --- |
| [`PcapParser`][pcap-parser] | Parse validated packets borrowing a byte slice. | [`pcap_parser_packet`][ex-pcap-parser-packet] |
| [`PcapReader::next_packet()`][pcap-reader-next-packet] | Process validated packets borrowing the reader buffer, one at a time. | [`pcap_reader_packet`][ex-pcap-reader-packet] |
| [`PcapReader::next_raw_packet()`][pcap-reader-next-raw-packet] | Inspect raw timestamp and length fields before validation. | [`pcap_reader_raw_packet`][ex-pcap-reader-raw-packet] |
| [`PcapPacketIterator`][pcap-packet-iterator] | Iterate over owned, validated packets you can retain. | [`pcap_reader_iterator`][ex-pcap-reader-iterator] |
| [`PcapWriter`][pcap-writer] | Create or copy Pcap captures with typed or raw packets. | [`pcap_writer_packet`][ex-pcap-writer-packet] |

## [PcapNg][pcapng-module]

### Choosing an API

| API | Use it to | Example |
| --- | --- | --- |
| [`PcapNgParser`][pcapng-parser] | Parse blocks borrowing a byte slice and track section/interface state. | [`pcapng_parser_block`][ex-pcapng-parser-block] |
| [`PcapNgReader::next_block()`][pcapng-reader-next-block] | Process borrowed, typed blocks and their metadata. | [`pcapng_reader_block`][ex-pcapng-reader-block] |
| [`PcapNgReader::next_raw_block()`][pcapng-reader-next-raw-block] | Inspect encoded fields or unsupported block types before typed decoding. | [`pcapng_reader_raw_block`][ex-pcapng-reader-raw-block] |
| [`PcapNgPacketIterator`][pcapng-packet-iterator] | Iterate over owned packets, skipping non-packet blocks. | [`pcapng_reader_iterator`][ex-pcapng-reader-iterator] |
| [`PcapNgWriter`][pcapng-writer] | Create or copy PcapNg captures while tracking section/interface state. | [`pcapng_writer_block`][ex-pcapng-writer-block] |
| [`CustomBlockPayload`][custom-block-payload] | Interpret custom block data. | [`pcapng_custom_block`][ex-pcapng-custom-block] |
| [`CustomOptionPayload`][custom-option-payload] | Interpret custom option data. | [`pcapng_custom_options`][ex-pcapng-custom-options] |

### Validation and raw blocks

- **Strict mode:** Pass `true` to [`PcapNgParser::new`][pcapng-parser-new],
  [`PcapNgReader::new`][pcapng-reader-new], or [`PcapNgWriter::new`][pcapng-writer-new] for semantic validation of typed blocks.
  With `false`, typed decoding and encoding still check representations and individual options.
- **State validity:** Parsers and readers always validate section and interface blocks, including on raw reads.
- **Manual decoding:** Call [`RawBlock::try_into_block`][raw-block-try-into-block],
  then [`Block::validate`][block-validate] with the current state for semantic checks.
- **Parser recovery:** On [`PcapNgParseError::Block`][pcapng-parse-error-block],
  call [`PcapNgParser::next_raw_block()`][pcapng-parser-next-raw-block] with the same slice to skip the block.

### Custom payloads

- **Traits:** Implement [`CustomBlockPayload`][custom-block-payload] or
  [`CustomOptionPayload`][custom-option-payload] alongside a payload codec trait.
- **Codec:** Use [`CustomPayloadCopiable`][custom-payload-copiable] when bytes can be
  copied unchanged between sections, or [`CustomPayloadNonCopiable`][custom-payload-non-copiable]
  when encoding depends on section or interface state.
- **Padding:** Decoded custom block payloads include alignment padding.
  Store a payload length or use a fixed aligned layout to distinguish it from your data.

## Fuzzing

See the [Rust Fuzz Book][cargo-fuzz-setup] for setup with a nightly toolchain,
a C++ compiler, and `cargo-fuzz`.
Run a target from the repository root:

```bash
cargo +nightly fuzz run pcap_reader
cargo +nightly fuzz run pcap_ng_reader
cargo +nightly fuzz run pcap_parser
cargo +nightly fuzz run pcap_ng_parser
```

See the [cargo-fuzz guide][cargo-fuzz-guide] for additional options.

## License

Licensed under [MIT][license].

PcapNg tests use [hadrielk's testing suite][pcapng-test-generator].

<!-- Links -->

[pcap-module]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/mod.rs#L1
[pcap-parser]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/parser.rs#L15-L47
[pcap-reader-next-packet]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/reader.rs#L96-L106
[pcap-reader-next-raw-packet]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/reader.rs#L140-L152
[pcap-packet-iterator]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/reader.rs#L225-L256
[pcap-writer]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/writer.rs#L15-L36
[pcapng-module]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/mod.rs#L1
[pcapng-parser]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/parser.rs#L14-L47
[pcapng-reader-next-block]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/reader.rs#L104-L121
[pcapng-reader-next-raw-block]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/reader.rs#L163-L180
[pcapng-packet-iterator]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/reader.rs#L269-L302
[pcapng-writer]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/writer.rs#L17-L40
[custom-block-payload]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/blocks/custom.rs#L108-L111
[custom-option-payload]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/blocks/custom.rs#L146-L149
[custom-payload-copiable]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/blocks/custom.rs#L25
[custom-payload-non-copiable]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/blocks/custom.rs#L65
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
[docs-home]: https://docs.rs/pcap-file/3.0.0-rc.3/pcap_file/
[license]: https://github.com/courvoif/pcap-file/blob/master/LICENSE
[pcapng-test-generator]: https://github.com/hadrielk/pcapng-test-generator
[cargo-fuzz-setup]: https://rust-fuzz.github.io/book/cargo-fuzz/setup.html
[cargo-fuzz-guide]: https://rust-fuzz.github.io/book/cargo-fuzz/guide.html
[std-read]: https://doc.rust-lang.org/std/io/trait.Read.html
[std-write]: https://doc.rust-lang.org/std/io/trait.Write.html
[std-none]: https://doc.rust-lang.org/std/option/enum.Option.html#variant.None
[std-unexpected-eof]: https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.UnexpectedEof
[pcap-reader-packets]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/reader.rs#L194-L198
[pcap-reader-with-capacity]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/reader.rs#L73-L81
[pcap-read-error-is-fatal]: https://github.com/courvoif/pcap-file/blob/master/src/pcap/errors.rs#L73
[pcapng-parser-new]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/parser.rs#L57-L72
[pcapng-parser-next-raw-block]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/parser.rs#L141-L156
[pcapng-reader-new]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/reader.rs#L54-L66
[pcapng-reader-packets]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/reader.rs#L237-L242
[pcapng-reader-with-capacity]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/reader.rs#L80-L90
[pcapng-read-error-is-fatal]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/errors.rs#L79
[raw-block-try-into-block]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/blocks/block_common.rs#L176-L184
[block-validate]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/blocks/block_common.rs#L383-L387
[pcapng-writer-new]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/writer.rs#L51-L73
[pcapng-parse-error-block]: https://github.com/courvoif/pcap-file/blob/master/src/pcapng/errors.rs#L25
